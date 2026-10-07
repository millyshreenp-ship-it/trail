"""Legitimate transaction patterns that can still look suspicious (false-positive pressure).

Patterns: student payments, shopkeeper settlements, refunds, gig workers,
high-volume businesses, shared household devices.
"""
from __future__ import annotations

import hashlib
import hmac
import random
from datetime import datetime, timedelta, timezone
from typing import Iterable

from app.models.transaction import Transaction
from app.security.tokens import TokenService, epoch_for

# Injected synthetic key. Replaces Python's salted hash() so tokens match across processes.
SIM_TOKEN_KEY = b"trail-synthetic-token-key-v1"

AMOUNT_BUCKETS = (
    "0_1k",
    "1k_10k",
    "10k_50k",
    "50k_100k",
    "100k_500k",
    "500k_plus",
)
RAILS = ("UPI", "IMPS", "NEFT")
INSTITUTIONS = ("BANK_A", "BANK_B", "BANK_C", "WALLET_W")
TX_TYPES = ("P2P", "P2M", "WALLET_LOAD", "REFUND", "SALARY")
MERCHANT_CATS = ("grocery", "fuel", "education", "utilities", "marketplace", None)


def _bucket_for_amount(amount: float) -> str:
    if amount < 1_000:
        return "0_1k"
    if amount < 10_000:
        return "1k_10k"
    if amount < 50_000:
        return "10k_50k"
    if amount < 100_000:
        return "50k_100k"
    if amount < 500_000:
        return "100k_500k"
    return "500k_plus"


def stable_reference_token(rail: str, ref: str, ts: datetime, key: bytes = SIM_TOKEN_KEY) -> str:
    """HMAC reference token for simulator fixtures. `key` is a test key, not a production secret."""
    epoch = epoch_for(ts)
    msg = rail.upper().encode() + b"\x1f" + ref.encode() + b"\x1f" + epoch.encode()
    digest = hmac.new(key, msg, hashlib.sha256).digest()[:16]
    return "tok_" + digest.hex()


def _tok(
    svc: TokenService | None,
    rail: str,
    ref: str,
    ts: datetime,
    *,
    key: bytes = SIM_TOKEN_KEY,
) -> str:
    if svc is None:
        return stable_reference_token(rail, ref, ts, key=key)
    return svc.reference_token(rail, ref, epoch_for(ts))


def _id(prefix: str, n: int) -> str:
    return f"{prefix}_{n:06d}"


def generate_legitimate_transactions(
    n: int = 5000,
    *,
    start: datetime | None = None,
    token_service: TokenService | None = None,
    rng: random.Random | None = None,
) -> list[Transaction]:
    """Generate realistic legitimate traffic with controlled false-positive hooks."""
    rng = rng or random.Random(42)
    start = start or datetime(2026, 9, 1, tzinfo=timezone.utc)
    txs: list[Transaction] = []

    # Pre-create a pool of long-lived accounts (age > 90 days relative to start)
    n_accounts = max(200, n // 20)
    accounts = [f"acct_legit_{i:04d}" for i in range(n_accounts)]
    account_inst = {a: rng.choice(INSTITUTIONS) for a in accounts}
    # Shared household / shop device tokens (legitimate multi-user)
    shared_devices = [f"dev_shared_{i}" for i in range(15)]
    personal_devices = {a: f"dev_{a}" for a in accounts}

    for i in range(n):
        ts = start + timedelta(
            minutes=rng.randint(0, 60 * 24 * 40),
            seconds=rng.randint(0, 59),
        )
        src = rng.choice(accounts)
        # Prefer same-institution or known counterparties for legitimacy
        if rng.random() < 0.55:
            dst = rng.choice(accounts)
        else:
            dst = f"acct_ext_{rng.randint(0, 500):04d}"
        src_inst = account_inst[src]
        dst_inst = account_inst.get(dst, rng.choice(INSTITUTIONS))
        rail = rng.choice(RAILS)
        # Amount distribution skewed small
        amount = abs(rng.gauss(2_500, 4_000)) + 50
        if rng.random() < 0.05:
            amount = abs(rng.gauss(45_000, 20_000))
        bucket = _bucket_for_amount(amount)
        tx_type = rng.choices(TX_TYPES, weights=[0.45, 0.25, 0.1, 0.1, 0.1])[0]
        merch = rng.choice(MERCHANT_CATS) if tx_type == "P2M" else None
        # Occasional shared device (household / shop POS)
        device = rng.choice(shared_devices) if rng.random() < 0.08 else personal_devices[src]
        ref = f"RRN{rng.randint(10**11, 10**12 - 1)}"
        ref_tok = _tok(token_service, rail, ref, ts)

        txs.append(
            Transaction(
                transaction_id=_id("tx_leg", i),
                rail=rail,
                timestamp=ts,
                source_institution=src_inst,
                destination_institution=dst_inst,
                source_token=src,
                destination_token=dst,
                amount_bucket=bucket,
                reference_token=ref_tok,
                device_token=device,
                merchant_category=merch,
                transaction_type=tx_type,
            )
        )
    txs.sort(key=lambda t: (t.timestamp, t.transaction_id))
    return txs


def legitimate_shopkeeper_burst(
    merchant: str = "acct_shop_001",
    institution: str = "BANK_B",
    n_customers: int = 40,
    *,
    day: datetime | None = None,
    token_service: TokenService | None = None,
    rng: random.Random | None = None,
) -> list[Transaction]:
    """High-volume legitimate merchant intake (looks like fan-in)."""
    rng = rng or random.Random(7)
    day = day or datetime(2026, 10, 2, 9, 0, tzinfo=timezone.utc)
    out: list[Transaction] = []
    for i in range(n_customers):
        ts = day + timedelta(minutes=rng.randint(0, 8 * 60))
        src = f"acct_cust_{i:03d}"
        rail = "UPI"
        amount = rng.uniform(80, 3_500)
        ref = f"RRN{900000000000 + i}"
        out.append(
            Transaction(
                transaction_id=_id("tx_shop", i),
                rail=rail,
                timestamp=ts,
                source_institution=rng.choice(INSTITUTIONS),
                destination_institution=institution,
                source_token=src,
                destination_token=merchant,
                amount_bucket=_bucket_for_amount(amount),
                reference_token=_tok(token_service, rail, ref, ts),
                device_token=f"dev_pos_{merchant}",
                merchant_category="grocery",
                transaction_type="P2M",
            )
        )
    return out


def legitimate_student_rent(
    student: str = "acct_student_01",
    landlord: str = "acct_landlord_01",
    *,
    months: int = 6,
    start: datetime | None = None,
    token_service: TokenService | None = None,
) -> list[Transaction]:
    """Monthly rent — regular, same parties, medium amount."""
    start = start or datetime(2026, 4, 1, 10, 0, tzinfo=timezone.utc)
    out: list[Transaction] = []
    for m in range(months):
        ts = start + timedelta(days=30 * m + (m % 3))
        rail = "UPI"
        ref = f"RENT{m:04d}"
        out.append(
            Transaction(
                transaction_id=_id("tx_rent", m),
                rail=rail,
                timestamp=ts,
                source_institution="BANK_A",
                destination_institution="BANK_B",
                source_token=student,
                destination_token=landlord,
                amount_bucket="10k_50k",
                reference_token=_tok(token_service, rail, ref, ts),
                device_token=f"dev_{student}",
                merchant_category=None,
                transaction_type="P2P",
            )
        )
    return out
