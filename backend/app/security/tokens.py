"""Keyed tokenisation (software keys; not HSM-backed).

token = Trunc128(HMAC-SHA256(K_epoch, rail || RRN || date))

A plain hash of a 12-digit RRN has only 10^12 inputs and can be brute-forced,
so we use a keyed HMAC with a daily-rotating epoch key. Matching accepts the
current and previous epoch. In production K_epoch lives in a KMS/HSM and the
upgrade path is an OPRF so the hub never sees plaintext references.
This is NOT audited cryptography.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import date, datetime, timedelta, timezone

SEP = b"\x1f"  # unit separator: avoids ambiguity between concatenated fields


def epoch_for(d: date | datetime | None = None) -> str:
    if d is None:
        d = datetime.now(timezone.utc)
    if isinstance(d, datetime):
        d = d.date()
    return d.isoformat()


def previous_epoch(epoch: str) -> str:
    return (date.fromisoformat(epoch) - timedelta(days=1)).isoformat()


class TokenService:
    def __init__(self, master_secret: bytes | None = None):
        secret = master_secret or os.environ.get("TRAIL_MASTER_SECRET", "").encode()
        if not secret:
            raise ValueError("TRAIL_MASTER_SECRET is not set. Put it in .env (never commit it).")
        if len(secret) < 16:
            raise ValueError("Master secret must be at least 16 bytes.")
        self._master = secret

    # -- key derivation -----------------------------------------------------
    def epoch_key(self, epoch: str) -> bytes:
        return hmac.new(self._master, b"epoch" + SEP + epoch.encode(), hashlib.sha256).digest()

    def case_key(self, case_id: str) -> bytes:
        return hmac.new(self._master, b"case" + SEP + case_id.encode(), hashlib.sha256).digest()

    # -- reference tokens ---------------------------------------------------
    def reference_token(self, rail: str, reference: str, epoch: str) -> str:
        msg = rail.upper().encode() + SEP + reference.encode() + SEP + epoch.encode()
        digest = hmac.new(self.epoch_key(epoch), msg, hashlib.sha256).digest()[:16]  # 128-bit
        return "tok_" + digest.hex()

    def candidate_tokens(self, rail: str, reference: str, epoch: str) -> set[str]:
        """Tokens valid for matching: current epoch and previous epoch."""
        return {
            self.reference_token(rail, reference, epoch),
            self.reference_token(rail, reference, previous_epoch(epoch)),
        }

    def matches(self, token: str, rail: str, reference: str, epoch: str) -> bool:
        return any(hmac.compare_digest(token, t) for t in self.candidate_tokens(rail, reference, epoch))

    # -- case-scoped account pseudonyms (Decision 4) --------------------------
    def case_pseudonym(self, case_id: str, account_id: str) -> str:
        """Same account -> different pseudonym in each case, so the hub cannot
        follow a person across unrelated cases without an approved ring merge."""
        d = hmac.new(self.case_key(case_id), account_id.encode(), hashlib.sha256).digest()[:12]
        return "acc_" + d.hex()
