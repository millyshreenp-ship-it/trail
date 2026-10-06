"""Server-reconstructed Ed25519 attestation and consent verification."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.models.preauth import ConsentRecord, EventAttestation
from app.security.canonical_json import canonical_json_bytes, sha256_hex

CLOCK_SKEW = timedelta(seconds=60)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("clock values must be timezone-aware")
    return value.astimezone(timezone.utc)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64url(value: str) -> bytes:
    if not value or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for ch in value):
        raise ValueError("invalid base64url signature")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def safe_event_envelope(event: Any) -> dict[str, Any]:
    """Rebuild the signed payload from allowlisted event fields only."""
    raw = event.model_dump(mode="json") if hasattr(event, "model_dump") else dict(event)
    allowed = (
        "schema_version", "event_id", "occurred_at", "institution_id", "event_source",
        "rail", "source_token", "payee_token", "amount_bucket", "payee_age_bucket",
        "session_context", "consent_scope", "trace_id", "idempotency_key",
    )
    return {key: raw[key] for key in allowed if key in raw}


def event_digest(event: Any) -> str:
    return sha256_hex(safe_event_envelope(event))


def consent_payload(record: ConsentRecord) -> dict[str, Any]:
    raw = record.model_dump(mode="json")
    allowed = (
        "consent_id", "subject_event_id", "granting_institution", "receiving_institution",
        "scope", "issued_at", "expires_at", "revoked_at", "event_digest", "verifier_key_version",
    )
    return {key: raw[key] for key in allowed}


def _sign(payload: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    return _b64url(private_key.sign(canonical_json_bytes(payload)))


@dataclass(frozen=True)
class KeyRecord:
    institution_id: str
    key_version: str
    public_key: Ed25519PublicKey
    algorithm: str = "Ed25519"
    active_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    def active(self, now: datetime) -> bool:
        now = _utc(now)
        return (
            self.algorithm == "Ed25519"
            and (self.active_at is None or now >= _utc(self.active_at))
            and (self.expires_at is None or now < _utc(self.expires_at))
            and (self.revoked_at is None or now < _utc(self.revoked_at))
        )


class KeyRegistry:
    def __init__(self, clock: Callable[[], datetime] | None = None):
        self._keys: dict[tuple[str, str], KeyRecord] = {}
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def register(
        self,
        institution_id: str,
        key_version: str,
        public_key: bytes | Ed25519PublicKey,
        *,
        active_at: datetime | None = None,
        expires_at: datetime | None = None,
        algorithm: str = "Ed25519",
    ) -> None:
        key = public_key if isinstance(public_key, Ed25519PublicKey) else Ed25519PublicKey.from_public_bytes(public_key)
        self._keys[(institution_id, key_version)] = KeyRecord(
            institution_id, key_version, key, algorithm, active_at, expires_at, None,
        )

    def revoke(self, institution_id: str, key_version: str, revoked_at: datetime | None = None) -> None:
        old = self._keys[(institution_id, key_version)]
        self._keys[(institution_id, key_version)] = KeyRecord(
            old.institution_id, old.key_version, old.public_key, old.algorithm,
            old.active_at, old.expires_at, revoked_at or _utc(self._clock()),
        )

    def resolve(self, institution_id: str, key_version: str, now: datetime | None = None) -> KeyRecord | None:
        record = self._keys.get((institution_id, key_version))
        return record if record and record.active(now or self._clock()) else None

    def is_active(self, institution_id: str, key_version: str, now: datetime | None = None) -> bool:
        return self.resolve(institution_id, key_version, now) is not None


@dataclass(frozen=True)
class AttestationResult:
    ok: bool
    reason: str = "OK"


class PreAuthAttestor:
    def __init__(self, registry: KeyRegistry, clock: Callable[[], datetime] | None = None):
        self.registry = registry
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def sign_event(
        self, event: Any, private_key: Ed25519PrivateKey, *, key_version: str,
        issued_at: datetime | None = None, expires_at: datetime | None = None,
    ) -> EventAttestation:
        issued = _utc(issued_at or self.clock())
        expiry = _utc(expires_at or (issued + timedelta(minutes=10)))
        payload = {"event_id": event.event_id, "institution_id": event.institution_id,
                   "event_digest": event_digest(event), "issued_at": issued.isoformat(),
                   "expires_at": expiry.isoformat(), "issuer_key_version": key_version}
        return EventAttestation(**payload, signature=_sign(payload, private_key))

    def verify_event(self, event: Any, attestation: EventAttestation, *, now: datetime | None = None) -> AttestationResult:
        current = _utc(now or self.clock())
        if attestation.event_id != event.event_id or attestation.institution_id != event.institution_id:
            return AttestationResult(False, "BINDING_MISMATCH")
        key = self.registry.resolve(attestation.institution_id, attestation.issuer_key_version, current)
        if key is None:
            return AttestationResult(False, "KEY_INACTIVE_OR_REVOKED")
        if attestation.event_digest != event_digest(event):
            return AttestationResult(False, "DIGEST_MISMATCH")
        if attestation.issued_at > current + CLOCK_SKEW:
            return AttestationResult(False, "ISSUED_IN_FUTURE")
        if current >= attestation.expires_at or attestation.expires_at <= attestation.issued_at:
            return AttestationResult(False, "EXPIRED")
        payload = {"event_id": attestation.event_id, "institution_id": attestation.institution_id,
                   "event_digest": attestation.event_digest, "issued_at": attestation.issued_at.isoformat(),
                   "expires_at": attestation.expires_at.isoformat(), "issuer_key_version": attestation.issuer_key_version}
        try:
            key.public_key.verify(_unb64url(attestation.signature), canonical_json_bytes(payload))
        except (InvalidSignature, ValueError):
            return AttestationResult(False, "BAD_SIGNATURE")
        return AttestationResult(True)


# Functional aliases keep the cryptographic contract convenient in tests.
def sign_event_attestation(event: Any, private_key: Ed25519PrivateKey, *, key_version: str, issued_at: datetime, expires_at: datetime) -> EventAttestation:
    registry = KeyRegistry()
    return PreAuthAttestor(registry).sign_event(event, private_key, key_version=key_version, issued_at=issued_at, expires_at=expires_at)


def verify_event_attestation(event: Any, attestation: EventAttestation, registry: KeyRegistry, *, now: datetime) -> bool:
    return PreAuthAttestor(registry, clock=lambda: now).verify_event(event, attestation, now=now).ok


def sign_consent(record: ConsentRecord, private_key: Ed25519PrivateKey) -> str:
    return _sign(consent_payload(record), private_key)


def verify_consent(record: ConsentRecord, registry: KeyRegistry, *, now: datetime, subject_event_digest: str, receiving_institution: str) -> AttestationResult:
    current = _utc(now)
    if record.event_digest != subject_event_digest or record.receiving_institution != receiving_institution:
        return AttestationResult(False, "CONSENT_BINDING_MISMATCH")
    key = registry.resolve(record.granting_institution, record.verifier_key_version, current)
    if key is None:
        return AttestationResult(False, "KEY_INACTIVE_OR_REVOKED")
    if record.revoked_at is not None and current >= record.revoked_at:
        return AttestationResult(False, "REVOKED")
    if current < record.issued_at or current >= record.expires_at:
        return AttestationResult(False, "EXPIRED")
    try:
        key.public_key.verify(_unb64url(record.signature), canonical_json_bytes(consent_payload(record)))
    except (InvalidSignature, ValueError):
        return AttestationResult(False, "BAD_SIGNATURE")
    return AttestationResult(True)


AttestationVerifier = PreAuthAttestor
