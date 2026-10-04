"""Beacon: the minimum information needed for cross-institution correlation.

No account numbers, balances, names or exact amounts ever appear here.
"""
from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, Field, field_validator

AMOUNT_BUCKETS = ["0_1k", "1k_10k", "10k_50k", "50k_100k", "100k_500k", "500k_plus"]
BUCKET_BOUNDS = [(0, 1_000), (1_000, 10_000), (10_000, 50_000), (50_000, 100_000),
                 (100_000, 500_000), (500_000, None)]


def amount_to_bucket(amount: float) -> str:
    for name, (lo, hi) in zip(AMOUNT_BUCKETS, BUCKET_BOUNDS):
        if amount >= lo and (hi is None or amount < hi):
            return name
    raise ValueError("negative amount")


def time_to_bucket(hour: int, minute: int, size: int = 5) -> str:
    """5-minute buckets per spec M4 (e.g. 10:32 -> '10:30')."""
    return f"{hour:02d}:{(minute // size) * size:02d}"


class EdgeType(str, Enum):
    COMPLAINT_SEED = "complaint_seed"
    DERIVED_FUNDS = "derived_funds"   # token_in -> token_out asserted by a bank
    BEHAVIOURAL = "behavioural"       # local score above threshold


class Beacon(BaseModel):
    token: str = Field(pattern=r"^tok_[0-9a-f]{32}$")
    parent_token: str | None = Field(default=None, pattern=r"^tok_[0-9a-f]{32}$")  # token_in for derived_funds
    epoch: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    rail: str
    amount_bucket: str
    time_bucket: str = Field(pattern=r"^\d{2}:\d{2}$")
    edge_type: EdgeType
    taint_lo_bucket: str | None = None
    taint_hi_bucket: str | None = None
    institution_id: str
    issued_at: int                    # unix seconds, covered by the signature
    ttl: int = Field(default=3600, gt=0, le=86_400)
    nonce: str = Field(default_factory=lambda: uuid.uuid4().hex)

    @field_validator("rail")
    @classmethod
    def _rail(cls, v: str) -> str:
        v = v.upper()
        if v not in {"UPI", "IMPS", "NEFT", "RTGS", "WALLET"}:
            raise ValueError("unsupported rail")
        return v

    @field_validator("amount_bucket", "taint_lo_bucket", "taint_hi_bucket")
    @classmethod
    def _bucket(cls, v):
        if v is not None and v not in AMOUNT_BUCKETS:
            raise ValueError("unknown amount bucket")
        return v

    model_config = {"extra": "forbid"}  # reject any field outside the minimum set


class SignedBeacon(BaseModel):
    beacon: Beacon
    signature: str  # base64 Ed25519 over canonical JSON of `beacon`
    model_config = {"extra": "forbid"}
