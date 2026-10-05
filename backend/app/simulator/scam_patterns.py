"""Scam-ring synthetic patterns: chain, fan-out, fan-in, cross-bank hop.

All amounts are synthetic. Tokens are account pseudonyms (not real customer data).
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Sequence

from app.models.transaction import Transaction
from app.security.tokens import TokenService

from app.simulator.legitimate import _bucket_for_amount, _id, _tok


def _base_ts() -> datetime:
    return datetime(2026, 10, 4, 10, 0, tzinfo=timezone.utc)


def generate_scam_chain(
    hops: Sequence[tuple[str, str]] | None = None,
    *,
    seed_amount: float = 78_000,
    start: datetime | None = None,
    token_service: TokenService | None = None,
    rng: random.Random | None = None,
) -> list[Transaction]:
    """Linear mule chain: victim → mule1 → mule2 → … → cash-out.

    hops: list of (institution, account_token). First is victim side destination.
    """
    rng = rng or random.Random(101)
    start = start or _base_ts()
    if hops is None:
        hops = (
            ("BANK_A", "acct_victim_seed"),
            ("BANK_B", "acct_mule_b1"),
            ("WALLET_W", "acct_mule_w1"),
            ("BANK_C", "acct_cashout_c1"),
        )
    txs: list[Transaction] = []
    prev_acct = hops[0][1]
    prev_inst = hops[0][0]
    # Seed inflow into first hop (complaint origin)
    t0 = start
    rail = "UPI"
    ref0 = f"SCAMSEED{rng.randint(1000, 9999)}"
    txs.append(
        Transaction(
            transaction_id=_id("tx_sc", 0),
            rail=rail,
            timestamp=t0,
            source_institution="BANK_A",
            destination_institution=prev_inst,
            source_token="acct_victim_external",
            destination_token=prev_acct,
            amount_bucket=_bucket_for_amount(seed_amount),
            reference_token=_tok(token_service, rail, ref0, t0),
            device_token="dev_victim",
            merchant_category=None,
            transaction_type="P2P",
        )
    )
    remaining = seed_amount
    for i, (inst, acct) in enumerate(hops[1:], start=1):
        # Rapid forward: 2–12 minutes
        delay = timedelta(minutes=rng.randint(2, 12), seconds=rng.randint(0, 50))
        ts = t0 + delay
        # Pass most of the funds, small leakage
        send_amt = remaining * rng.uniform(0.82, 0.97)
        remaining = send_amt
        ref = f"SCAMCH{i:03d}{rng.randint(10, 99)}"
        txs.append(
            Transaction(
                transaction_id=_id("tx_sc", i),
                rail=rail,
                timestamp=ts,
                source_institution=prev_inst,
                destination_institution=inst,
                source_token=prev_acct,
                destination_token=acct,
                amount_bucket=_bucket_for_amount(send_amt),
                reference_token=_tok(token_service, rail, ref, ts),
                device_token=f"dev_{prev_acct}",
                merchant_category=None,
                transaction_type="P2P",
            )
        )
        prev_acct, prev_inst = acct, inst
        t0 = ts
    return txs


def generate_scam_fanout(
    origin: tuple[str, str] = ("BANK_A", "acct_fan_origin"),
    leaves: Sequence[tuple[str, str]] | None = None,
    *,
    seed_amount: float = 120_000,
    start: datetime | None = None,
    token_service: TokenService | None = None,
    rng: random.Random | None = None,
) -> list[Transaction]:
    """One account rapidly disperses to many new beneficiaries."""
    rng = rng or random.Random(202)
    start = start or _base_ts()
    if leaves is None:
        leaves = (
            ("BANK_B", "acct_leaf_b1"),
            ("BANK_B", "acct_leaf_b2"),
            ("WALLET_W", "acct_leaf_w1"),
            ("BANK_C", "acct_leaf_c1"),
            ("BANK_C", "acct_leaf_c2"),
        )
    txs: list[Transaction] = []
    o_inst, o_acct = origin
    # Inflow
    t_in = start
    rail = "UPI"
    txs.append(
        Transaction(
            transaction_id=_id("tx_fo", 0),
            rail=rail,
            timestamp=t_in,
            source_institution="BANK_A",
            destination_institution=o_inst,
            source_token="acct_victim_fo",
            destination_token=o_acct,
            amount_bucket=_bucket_for_amount(seed_amount),
            reference_token=_tok(token_service, rail, "FOSEED001", t_in),
            device_token=f"dev_{o_acct}",
            merchant_category=None,
            transaction_type="P2P",
        )
    )
    share = seed_amount / len(leaves)
    for i, (inst, acct) in enumerate(leaves, start=1):
        ts = t_in + timedelta(minutes=rng.randint(1, 8), seconds=rng.randint(0, 40))
        amt = share * rng.uniform(0.85, 1.05)
        txs.append(
            Transaction(
                transaction_id=_id("tx_fo", i),
                rail=rail,
                timestamp=ts,
                source_institution=o_inst,
                destination_institution=inst,
                source_token=o_acct,
                destination_token=acct,
                amount_bucket=_bucket_for_amount(amt),
                reference_token=_tok(token_service, rail, f"FOUT{i:03d}", ts),
                device_token=f"dev_{o_acct}",
                merchant_category=None,
                transaction_type="P2P",
            )
        )
    return txs


def generate_scam_fanin(
    sinks: Sequence[tuple[str, str]] | None = None,
    collector: tuple[str, str] = ("BANK_C", "acct_collector"),
    *,
    per_leg: float = 25_000,
    start: datetime | None = None,
    token_service: TokenService | None = None,
    rng: random.Random | None = None,
) -> list[Transaction]:
    """Many accounts funnel into one collector then a single hop out."""
    rng = rng or random.Random(303)
    start = start or _base_ts()
    if sinks is None:
        sinks = (
            ("BANK_A", "acct_src_a1"),
            ("BANK_A", "acct_src_a2"),
            ("BANK_B", "acct_src_b1"),
            ("WALLET_W", "acct_src_w1"),
        )
    txs: list[Transaction] = []
    c_inst, c_acct = collector
    rail = "UPI"
    for i, (inst, acct) in enumerate(sinks):
        ts = start + timedelta(minutes=rng.randint(0, 20))
        amt = per_leg * rng.uniform(0.9, 1.1)
        txs.append(
            Transaction(
                transaction_id=_id("tx_fi", i),
                rail=rail,
                timestamp=ts,
                source_institution=inst,
                destination_institution=c_inst,
                source_token=acct,
                destination_token=c_acct,
                amount_bucket=_bucket_for_amount(amt),
                reference_token=_tok(token_service, rail, f"FIIN{i:03d}", ts),
                device_token=f"dev_{acct}",
                merchant_category=None,
                transaction_type="P2P",
            )
        )
    # Collector forwards quickly
    t_out = start + timedelta(minutes=25)
    total = per_leg * len(sinks) * 0.9
    txs.append(
        Transaction(
            transaction_id=_id("tx_fi", len(sinks)),
            rail=rail,
            timestamp=t_out,
            source_institution=c_inst,
            destination_institution="BANK_C",
            source_token=c_acct,
            destination_token="acct_cashout_fi",
            amount_bucket=_bucket_for_amount(total),
            reference_token=_tok(token_service, rail, "FIOUT001", t_out),
            device_token=f"dev_{c_acct}",
            merchant_category=None,
            transaction_type="P2P",
        )
    )
    return txs


def generate_cross_bank_hop(
    *,
    seed_amount: float = 78_000,
    start: datetime | None = None,
    token_service: TokenService | None = None,
    rng: random.Random | None = None,
) -> list[Transaction]:
    """Canonical north-star path: Bank A → Bank B → Wallet → Bank C."""
    return generate_scam_chain(
        hops=(
            ("BANK_A", "acct_seed_a"),
            ("BANK_B", "acct_hop_b"),
            ("WALLET_W", "acct_hop_w"),
            ("BANK_C", "acct_hop_c"),
        ),
        seed_amount=seed_amount,
        start=start,
        token_service=token_service,
        rng=rng,
    )
