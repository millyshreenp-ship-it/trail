"""Runtime configuration for sandbox and local/staging EarlyTrace operation."""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

VERSION = "1.0.0"
_DEFAULT_SECRET = "dev-only-master-secret-change-me"
PROFILE_SANDBOX = "sandbox"
PROFILE_STAGING = "staging"
PROFILE_PRODUCTION_UNSUPPORTED = "production_unsupported"
PROFILES = frozenset({PROFILE_SANDBOX, PROFILE_STAGING, PROFILE_PRODUCTION_UNSUPPORTED})
_PROFILE_ALIASES = {"production": PROFILE_PRODUCTION_UNSUPPORTED}
_INSTITUTION = re.compile(r"^[A-Z][A-Z0-9_]{1,32}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


def _normalise_profile(value: str) -> str:
    value = value.strip().lower()
    return _PROFILE_ALIASES.get(value, value)


def _profile_from_environment() -> str:
    return _normalise_profile(os.environ.get("TRAIL_PROFILE") or os.environ.get("TRAIL_ENV", PROFILE_SANDBOX))


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() not in {"", "0", "false", "no", "off"}


def _origin_is_local_or_wildcard(origin: str) -> bool:
    if "*" in origin or origin in {"null"}:
        return True
    try:
        host = (urlparse(origin).hostname or "").lower()
    except ValueError:
        return True
    return host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"} or not host


@dataclass(frozen=True)
class Settings:
    """Environment-backed settings with an explicit operational profile.

    ``production`` remains accepted as a compatibility spelling, but maps to
    ``production_unsupported`` and cannot start.  No profile enables live
    integrations; EarlyTrace remains synthetic/local-only in this repository.
    """

    env: str = field(default_factory=lambda: os.environ.get("TRAIL_ENV", PROFILE_SANDBOX).lower())
    profile: str = field(default_factory=_profile_from_environment)
    master_secret: str = field(default_factory=lambda: os.environ.get("TRAIL_MASTER_SECRET", _DEFAULT_SECRET))
    cors_origins: tuple[str, ...] = field(default_factory=lambda: tuple(
        origin.strip() for origin in os.environ.get(
            "TRAIL_CORS_ORIGINS", "http://localhost:5173,http://localhost:8000"
        ).split(",") if origin.strip()
    ))
    audit_path: str | None = field(default_factory=lambda: os.environ.get("TRAIL_AUDIT_PATH") or None)
    preauth_path: str = field(default_factory=lambda: os.environ.get("TRAIL_PREAUTH_PATH", ":memory:"))
    dependency_lock_path: str | None = field(default_factory=lambda: os.environ.get("TRAIL_DEPENDENCY_LOCK") or None)
    log_level: str = field(default_factory=lambda: os.environ.get("TRAIL_LOG_LEVEL", "INFO").upper())
    live_integrations: bool = field(default_factory=lambda: _bool(os.environ.get("TRAIL_LIVE_INTEGRATIONS")))
    data_status: str = field(default_factory=lambda: os.environ.get("TRAIL_DATA_STATUS", "synthetic").lower())

    def __post_init__(self) -> None:
        # Preserve callers that construct Settings(env="staging") directly,
        # while an explicit TRAIL_PROFILE always wins when present.
        if "TRAIL_PROFILE" not in os.environ and self.env.lower() != os.environ.get("TRAIL_ENV", PROFILE_SANDBOX).lower():
            object.__setattr__(self, "profile", _normalise_profile(self.env))
        else:
            object.__setattr__(self, "profile", _normalise_profile(self.profile))

    @property
    def is_production(self) -> bool:
        return self.profile == PROFILE_PRODUCTION_UNSUPPORTED

    @property
    def is_staging(self) -> bool:
        return self.profile == PROFILE_STAGING

    @property
    def demo_keys_enabled(self) -> bool:
        return self.profile == PROFILE_SANDBOX and os.environ.get("TRAIL_DISABLE_DEV_KEYS") != "1"

    @property
    def storage_mode(self) -> str:
        return "memory" if self.preauth_path == ":memory:" else "sqlite_wal"

    @property
    def docs_enabled(self) -> bool:
        return self.profile == PROFILE_SANDBOX

    def _durable_path_error(self, name: str, value: str | None) -> str | None:
        if not value or value == ":memory:":
            return f"{name} must point to durable local storage"
        parent = Path(value).expanduser().parent
        if not parent.exists() or not parent.is_dir():
            return f"{name} parent directory must exist"
        return None

    def validation_errors(self) -> tuple[str, ...]:
        problems: list[str] = []
        if self.profile not in PROFILES:
            problems.append("TRAIL_PROFILE must be sandbox, staging, or production_unsupported")
        if self.live_integrations:
            problems.append("TRAIL_LIVE_INTEGRATIONS must remain false")
        if self.data_status != "synthetic":
            problems.append("TRAIL_DATA_STATUS must be synthetic")

        if self.profile == PROFILE_PRODUCTION_UNSUPPORTED:
            problems.append("production_unsupported is intentionally not deployable")

        if self.profile in {PROFILE_STAGING, PROFILE_PRODUCTION_UNSUPPORTED}:
            if self.master_secret == _DEFAULT_SECRET or len(self.master_secret) < 32:
                problems.append("TRAIL_MASTER_SECRET must be a strong non-demo value")
            if self.demo_keys_enabled or os.environ.get("TRAIL_DISABLE_DEV_KEYS") != "1":
                problems.append("sandbox/demo API keys must be disabled")
            users_raw = os.environ.get("TRAIL_USERS_JSON", "")
            try:
                users = json.loads(users_raw) if users_raw else {}
            except (TypeError, ValueError):
                users = {}
            if not isinstance(users, dict) or not users:
                problems.append("TRAIL_USERS_JSON must contain institution-bound hashed users")
            else:
                for digest, principal in users.items():
                    if not isinstance(digest, str) or not _HASH.fullmatch(digest):
                        problems.append("TRAIL_USERS_JSON keys must be SHA-256 digests")
                        break
                    if not isinstance(principal, dict) or not _INSTITUTION.fullmatch(str(principal.get("institution", ""))):
                        problems.append("every configured user must have an institution")
                        break
            for origin in self.cors_origins:
                if _origin_is_local_or_wildcard(origin):
                    problems.append("staging CORS must not allow localhost, null, wildcard, or empty origins")
                    break
            if not self.cors_origins:
                problems.append("staging CORS must contain an explicit non-local origin")
            for name, value in (("TRAIL_AUDIT_PATH", self.audit_path), ("TRAIL_PREAUTH_PATH", self.preauth_path)):
                if (error := self._durable_path_error(name, value)):
                    problems.append(error)
            if not self.dependency_lock_path or not Path(self.dependency_lock_path).is_file():
                problems.append("TRAIL_DEPENDENCY_LOCK must point to a checked-in dependency lock")
        return tuple(dict.fromkeys(problems))

    def dependency_lock_verified(self) -> bool:
        """Verify the image-installed lock marker matches the configured lock."""
        if not self.dependency_lock_path:
            return False
        lock = Path(self.dependency_lock_path)
        if not lock.is_file():
            return False
        marker = Path(str(lock) + ".sha256")
        if not marker.is_file():
            return False
        expected = marker.read_text(encoding="utf-8").strip().split()[0] if marker.read_text(encoding="utf-8").strip() else ""
        actual = hashlib.sha256(lock.read_bytes()).hexdigest()
        return bool(expected) and hmac_compare(expected, actual)

    def validate(self) -> None:
        """Fail fast for unsupported or unsafe startup configuration."""
        problems = self.validation_errors()
        if problems:
            prefix = "Unsafe production configuration" if self.env.lower() == "production" else "Unsafe Trail configuration"
            raise RuntimeError(prefix + ": " + "; ".join(problems))


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time comparison for the lock marker, without exposing values."""
    import hmac
    return hmac.compare_digest(left, right)


def get_settings() -> Settings:
    return Settings()
