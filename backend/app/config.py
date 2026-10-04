"""Runtime configuration (12-factor: everything from environment variables)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

VERSION = "1.0.0"
_DEFAULT_SECRET = "dev-only-master-secret-change-me"


@dataclass(frozen=True)
class Settings:
    env: str = field(default_factory=lambda: os.environ.get("TRAIL_ENV", "sandbox").lower())
    master_secret: str = field(default_factory=lambda: os.environ.get("TRAIL_MASTER_SECRET", _DEFAULT_SECRET))
    cors_origins: tuple = field(default_factory=lambda: tuple(
        o.strip() for o in os.environ.get("TRAIL_CORS_ORIGINS", "http://localhost:5173,http://localhost:8000").split(",") if o.strip()))
    audit_path: str | None = field(default_factory=lambda: os.environ.get("TRAIL_AUDIT_PATH") or None)
    log_level: str = field(default_factory=lambda: os.environ.get("TRAIL_LOG_LEVEL", "INFO").upper())

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    def validate(self) -> None:
        """Fail fast on unsafe production configuration."""
        if not self.is_production:
            return
        problems = []
        if self.master_secret == _DEFAULT_SECRET or len(self.master_secret) < 32:
            problems.append("TRAIL_MASTER_SECRET must be set to 32+ random characters")
        if not os.environ.get("TRAIL_USERS_JSON"):
            problems.append("TRAIL_USERS_JSON (hashed API keys) must be provided")
        if not self.audit_path:
            problems.append("TRAIL_AUDIT_PATH must point to durable storage")
        if any("localhost" in o for o in self.cors_origins):
            problems.append("TRAIL_CORS_ORIGINS must not include localhost")
        if problems:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(problems))


def get_settings() -> Settings:
    return Settings()
