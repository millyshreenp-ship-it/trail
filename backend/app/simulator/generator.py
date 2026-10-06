"""Synthetic transaction world generator (Khanak Part 1).

Public entry points:
  - generate_dataset(...)
  - generate_legitimate_transactions / generate_scam_* (re-exported)
  - write_synthetic_jsonl / load helpers

Uses only synthetic tokens. When a TokenService is supplied, reference_token
values are real HMAC tokens so they join with beacons/complaints.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from app.models.transaction import Transaction
from app.security.tokens import TokenService

from app.simulator.legitimate import (
    LOOKALIKE_LEGIT_ACCOUNTS,
    generate_legitimate_transactions,
    legitimate_gig_worker,
    legitimate_high_volume_business,
    legitimate_refund_pair,
    legitimate_shopkeeper_burst,
    legitimate_student_rent,
)
from app.simulator.scam_patterns import (
    generate_cross_bank_hop,
    generate_scam_chain,
    generate_scam_fanin,
    generate_scam_fanout,
)
from app.simulator.scenarios import (
    scenario_mixed_patterns,
    scenario_north_star,
    scenario_ring_with_legit_receiver,
)

__all__ = [
    "generate_dataset",
    "generate_legitimate_transactions",
    "generate_scam_chain",
    "generate_scam_fanout",
    "generate_scam_fanin",
    "generate_cross_bank_hop",
    "scenario_north_star",
    "scenario_mixed_patterns",
    "scenario_ring_with_legit_receiver",
    "write_synthetic_jsonl",
    "transactions_to_dicts",
]


def generate_dataset(
    *,
    n_legitimate: int = 5000,
    n_suspicious: int = 500,
    include_known_rings: bool = True,
    token_service: TokenService | None = None,
    seed: int = 42,
) -> dict[str, Any]:
    """Build a full synthetic corpus matching the execution-plan scale.

    Returns:
      {
        "transactions": list[Transaction],
        "labels": dict[str, str],          # account_token -> label
        "rings": list[list[Transaction]],  # known scam-ring subsets
        "meta": {...}
      }
    """
    rng = random.Random(seed)
    start = datetime(2026, 9, 1, tzinfo=timezone.utc)

    legit = generate_legitimate_transactions(
        n_legitimate, start=start, token_service=token_service, rng=rng
    )
    # Inject legitimate lookalikes that stress false positives
    shop = legitimate_shopkeeper_burst(token_service=token_service, rng=rng)
    rent = legitimate_student_rent(token_service=token_service)
    lookalikes = (
        shop + rent
        + legitimate_refund_pair(token_service=token_service)
        + legitimate_gig_worker(token_service=token_service, rng=random.Random(seed + 11))
        + legitimate_high_volume_business(token_service=token_service, rng=random.Random(seed + 13))
    )

    rings: list[list[Transaction]] = []
    ring_meta: list[dict[str, Any]] = []
    labels: dict[str, str] = {}
    suspicious: list[Transaction] = []

    if include_known_rings:
        chain = generate_scam_chain(token_service=token_service, rng=random.Random(seed + 1))
        fanout = generate_scam_fanout(token_service=token_service, rng=random.Random(seed + 2))
        fanin = generate_scam_fanin(token_service=token_service, rng=random.Random(seed + 3))
        hop = generate_cross_bank_hop(token_service=token_service, rng=random.Random(seed + 4))
        for subset, tag in (
            (_namespace(chain, "k0"), "chain"),
            (_namespace(fanout, "k1"), "fanout"),
            (_namespace(fanin, "k2"), "fanin"),
            (_namespace(hop, "k3"), "cross_bank_hop"),
        ):
            rings.append(subset)
            ring_meta.append(_ring_meta(subset, tag))
            suspicious.extend(subset)
            for t in subset:
                labels[t.source_token] = labels.get(t.source_token, "mule")
                labels[t.destination_token] = "mule"
            # Origin / seed accounts
            if subset:
                labels[subset[0].destination_token] = "scam_ring"

    # Pad suspicious volume with varied extra rings until the target is reached
    k = 0
    while len(suspicious) < n_suspicious:
        extra, tag = _padded_ring(k, rng, start, token_service)
        extra = _namespace(extra, f"x{k}")
        k += 1
        rings.append(extra)
        ring_meta.append(_ring_meta(extra, tag))
        suspicious.extend(extra)
        for t in extra:
            labels[t.destination_token] = "mule"

    for acct in LOOKALIKE_LEGIT_ACCOUNTS:
        labels[acct] = "legit"

    all_txs = sorted(legit + lookalikes + suspicious, key=lambda t: t.timestamp)
    return {
        "transactions": all_txs,
        "labels": labels,
        "rings": rings,
        "ring_meta": ring_meta,  # [{"pattern", "seed", "members"}] aligned with `rings`
        "meta": {
            "n_legitimate": len(legit) + len(lookalikes),
            "n_suspicious": len(suspicious),
            "n_total": len(all_txs),
            "n_rings": len(rings),
            "seed": seed,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def _ring_meta(subset: list[Transaction], pattern: str) -> dict[str, Any]:
    """Ground truth for one ring: complaint seed + all mule/ring accounts (victim excluded).

    Seed = first account that receives victim money; for fan-in that is the first feeder.
    """
    first = subset[0]
    seed = first.source_token if pattern == "fanin" else first.destination_token
    members = {t.source_token for t in subset} | {t.destination_token for t in subset}
    if pattern != "fanin":
        members.discard(first.source_token)  # the victim's own account is not part of the ring
    return {"pattern": pattern, "seed": seed, "members": sorted(members)}


def _namespace(txs: list[Transaction], tag: str) -> list[Transaction]:
    """Make transaction_ids unique per ring (the pattern generators use fixed id prefixes)."""
    return [t.model_copy(update={"transaction_id": f"{t.transaction_id}_{tag}"}) for t in txs]


def _padded_ring(
    k: int, rng: random.Random, start: datetime, token_service: TokenService | None
) -> tuple[list[Transaction], str]:
    """Varied extra ring #k: rotates chain / fan-out / fan-in / cross-bank hop, random size and bank mix."""
    insts = ("BANK_A", "BANK_B", "BANK_C", "WALLET_W")
    pattern = ("chain", "fanout", "fanin", "cross_bank_hop")[k % 4]
    ts = start.replace(day=1 + (k % 28), hour=8 + (k % 12), minute=rng.randint(0, 40))
    amt = rng.uniform(15_000, 190_000)
    sub = random.Random(rng.randint(0, 10**9))
    if pattern in ("chain", "cross_bank_hop"):
        n = rng.randint(3, 5)
        names = [f"acct_p{k}_m{i}" for i in range(n)]
        if pattern == "cross_bank_hop":
            order = ["BANK_A", "BANK_B", "WALLET_W", "BANK_C", "BANK_B"][:n]
        else:
            order = [rng.choice(insts) for _ in range(n)]
        txs = generate_scam_chain(hops=tuple(zip(order, names)), seed_amount=amt, start=ts,
                                  token_service=token_service, rng=sub)
    elif pattern == "fanout":
        m = rng.randint(3, 6)
        leaves = tuple((rng.choice(insts), f"acct_p{k}_leaf{i}") for i in range(m))
        txs = generate_scam_fanout(origin=(rng.choice(insts), f"acct_p{k}_origin"), leaves=leaves,
                                   seed_amount=amt, start=ts, token_service=token_service, rng=sub)
    else:
        m = rng.randint(3, 5)
        sinks = tuple((rng.choice(insts), f"acct_p{k}_src{i}") for i in range(m))
        txs = generate_scam_fanin(sinks=sinks, collector=(rng.choice(insts), f"acct_p{k}_collector"),
                                  per_leg=amt / m, start=ts, token_service=token_service, rng=sub)
        txs = [t.model_copy(update={"destination_token": f"acct_p{k}_cashout"})
               if t.destination_token == "acct_cashout_fi" else t for t in txs]
    return txs, pattern


def transactions_to_dicts(txs: Iterable[Transaction]) -> list[dict]:
    return [t.model_dump(mode="json") for t in txs]


def write_synthetic_jsonl(
    path: str | Path,
    transactions: Iterable[Transaction],
) -> int:
    """Write transactions as JSON Lines. Returns count written."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for t in transactions:
            f.write(json.dumps(t.model_dump(mode="json"), default=str) + "\n")
            n += 1
    return n
