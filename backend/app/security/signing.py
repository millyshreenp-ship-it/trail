"""Beacon signing and verification (software keys; not HSM-backed; uses the `cryptography` library's Ed25519).

Checks performed on every beacon, in order:
  1. institution is registered and not revoked        (institution authentication)
  2. beacon.institution_id matches the claimed sender  (no impersonation)
  3. Ed25519 signature over canonical JSON is valid     (integrity)
  4. epoch is current or previous                       (token rotation window)
  5. issued_at not in the future; now < issued_at + ttl (expiry / TTL)
  6. nonce not seen before                              (replay protection)
  7. per-institution influence cap not exceeded         (malicious-institution limit)
In production add mTLS at the transport layer and keys in a KMS/HSM.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.models.beacon import Beacon, SignedBeacon
from app.security.ratelimit import SlidingWindowLimiter
from app.security.tokens import epoch_for, previous_epoch

CLOCK_SKEW_S = 60


def canonical_bytes(beacon: Beacon) -> bytes:
    return json.dumps(beacon.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()


def generate_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub


def sign_beacon(beacon: Beacon, private_key: Ed25519PrivateKey) -> SignedBeacon:
    sig = private_key.sign(canonical_bytes(beacon))
    return SignedBeacon(beacon=beacon, signature=base64.b64encode(sig).decode())


@dataclass
class VerificationResult:
    ok: bool
    reason: str = "OK"


class InstitutionRegistry:
    """Public keys of enrolled institutions. Supports revocation."""

    def __init__(self):
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._revoked: set[str] = set()

    def register(self, institution_id: str, public_key_raw: bytes) -> None:
        self._keys[institution_id] = Ed25519PublicKey.from_public_bytes(public_key_raw)
        self._revoked.discard(institution_id)

    def revoke(self, institution_id: str) -> None:
        self._revoked.add(institution_id)

    def is_active(self, institution_id: str) -> bool:
        return institution_id in self._keys and institution_id not in self._revoked

    def public_key(self, institution_id: str) -> Ed25519PublicKey | None:
        return self._keys.get(institution_id)

    def institutions(self) -> list[str]:
        return sorted(i for i in self._keys if i not in self._revoked)


class BeaconVerifier:
    def __init__(self, registry: InstitutionRegistry,
                 clock: Callable[[], float] = time.time,
                 influence_cap: int = 200, influence_window_s: float = 3600):
        self.registry = registry
        self._clock = clock
        self._seen_nonces: dict[str, float] = {}  # nonce -> expiry
        self._lock = threading.Lock()
        self._limiter = SlidingWindowLimiter(influence_cap, influence_window_s, clock)

    def _purge(self, now: float) -> None:
        for n in [n for n, exp in self._seen_nonces.items() if exp < now]:
            del self._seen_nonces[n]

    def verify(self, signed: SignedBeacon, claimed_institution: str) -> VerificationResult:
        b = signed.beacon
        now = self._clock()

        if not self.registry.is_active(claimed_institution):
            return VerificationResult(False, "UNKNOWN_OR_REVOKED_INSTITUTION")
        if b.institution_id != claimed_institution:
            return VerificationResult(False, "INSTITUTION_MISMATCH")

        try:
            sig = base64.b64decode(signed.signature, validate=True)
            self.registry.public_key(claimed_institution).verify(sig, canonical_bytes(b))
        except (InvalidSignature, ValueError):
            return VerificationResult(False, "BAD_SIGNATURE")

        current = epoch_for(datetime.fromtimestamp(now, tz=timezone.utc))
        if b.epoch not in (current, previous_epoch(current)):
            return VerificationResult(False, "STALE_EPOCH")

        if b.issued_at > now + CLOCK_SKEW_S:
            return VerificationResult(False, "ISSUED_IN_FUTURE")
        if now >= b.issued_at + b.ttl:
            return VerificationResult(False, "EXPIRED")

        with self._lock:
            self._purge(now)
            if b.nonce in self._seen_nonces:
                return VerificationResult(False, "REPLAY")
            if not self._limiter.allow(claimed_institution):
                return VerificationResult(False, "INFLUENCE_CAP_EXCEEDED")
            self._seen_nonces[b.nonce] = b.issued_at + b.ttl + CLOCK_SKEW_S
        return VerificationResult(True)
