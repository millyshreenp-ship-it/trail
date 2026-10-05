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
    generate_legitimate_transactions,
    legitimate_shopkeeper_burst,
    legitimate_student_rent,
)
from app.simulator.scam_patterns import (
    generate_cross_bank_hop,
    generate_scam_chain,
    generate_scam_fanin,
    generate_scam_fanout,
)
from app.simulator.scenarios import scenario_mixed_patterns, scenario_north_star

__all__ = [
    "generate_dataset",
    "generate_legitimate_transactions",
    "generate_scam_chain",
    "generate_scam_fanout",
    "generate_scam_fanin",
    "generate_cross_bank_hop",
    "scenario_north_star",
    "scenario_mixed_patterns",
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

    rings: list[list[Transaction]] = []
    labels: dict[str, str] = {}
    suspicious: list[Transaction] = []

    if include_known_rings:
        chain = generate_scam_chain(token_service=token_service, rng=random.Random(seed + 1))
        fanout = generate_scam_fanout(token_service=token_service, rng=random.Random(seed + 2))
        fanin = generate_scam_fanin(token_service=token_service, rng=random.Random(seed + 3))
        hop = generate_cross_bank_hop(token_service=token_service, rng=random.Random(seed + 4))
        for subset, tag in (
            (chain, "chain"),
            (fanout, "fanout"),
            (fanin, "fanin"),
            (hop, "cross_bank_hop"),
        ):
            rings.append(subset)
            suspicious.extend(subset)
            for t in subset:
                labels[t.source_token] = labels.get(t.source_token, "mule")
                labels[t.destination_token] = "mule"
            # Origin / seed accounts
            if subset:
                labels[subset[0].destination_token] = "scam_ring"

    # Pad suspicious volume with additional short chains if needed
    extra_needed = max(0, n_suspicious - len(suspicious))
    for k in range(extra_needed // 4 + 1):
        if len(suspicious) >= n_suspicious:
            break
        extra = generate_scam_chain(
            hops=(
                ("BANK_A", f"acct_xseed_{k}"),
                ("BANK_B", f"acct_xmule_{k}a"),
                ("BANK_C", f"acct_xmule_{k}b"),
            ),
            seed_amount=rng.uniform(15_000, 90_000),
            start=start.replace(day=min(28, 5 + k)),
            token_service=token_service,
            rng=random.Random(seed + 100 + k),
        )
        rings.append(extra)
        suspicious.extend(extra)
        for t in extra:
            labels[t.destination_token] = "mule"

    labels["acct_shop_001"] = "legit"
    labels["acct_student_01"] = "legit"
    labels["acct_landlord_01"] = "legit"

    all_txs = sorted(legit + shop + rent + suspicious, key=lambda t: t.timestamp)
    return {
        "transactions": all_txs,
        "labels": labels,
        "rings": rings,
        "meta": {
            "n_legitimate": len(legit) + len(shop) + len(rent),
            "n_suspicious": len(suspicious),
            "n_total": len(all_txs),
            "n_rings": len(rings),
            "seed": seed,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }


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
