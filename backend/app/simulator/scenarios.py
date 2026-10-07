"""Named end-to-end scenarios for demos and evaluation.

Each scenario returns a dict with:
  - transactions: list[Transaction]
  - labels: dict[account_token, "legit" | "scam_ring" | "mule" | ...]
  - meta: free-form description
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

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


def scenario_north_star(
    *,
    token_service: TokenService | None = None,
    n_background: int = 2000,
) -> dict[str, Any]:
    """The 48-hour MVP demo scenario: one cross-bank scam ring inside background traffic."""
    start = datetime(2026, 9, 20, tzinfo=timezone.utc)
    legit = generate_legitimate_transactions(
        n_background, start=start, token_service=token_service
    )
    shop = legitimate_shopkeeper_burst(token_service=token_service)
    rent = legitimate_student_rent(token_service=token_service)
    ring = generate_cross_bank_hop(
        seed_amount=78_000,
        start=datetime(2026, 10, 4, 10, 32, tzinfo=timezone.utc),
        token_service=token_service,
    )
    txs = sorted(legit + shop + rent + ring, key=lambda t: t.timestamp)
    labels = {
        "acct_seed_a": "scam_ring",
        "acct_hop_b": "mule",
        "acct_hop_w": "mule",
        "acct_hop_c": "mule",
        "acct_shop_001": "legit",
        "acct_student_01": "legit",
        "acct_landlord_01": "legit",
    }
    return {
        "name": "north_star_cross_bank",
        "transactions": txs,
        "labels": labels,
        "meta": {
            "seed_amount": 78_000,
            "institutions": ["BANK_A", "BANK_B", "WALLET_W", "BANK_C"],
            "pattern": "cross_bank_hop",
            "description": "Victim funds hop A→B→Wallet→C inside realistic background traffic",
        },
    }


def scenario_mixed_patterns(
    *,
    token_service: TokenService | None = None,
    n_background: int = 3000,
) -> dict[str, Any]:
    """Multiple scam morphologies + legitimate lookalikes for feature/scorer eval."""
    start = datetime(2026, 9, 15, tzinfo=timezone.utc)
    legit = generate_legitimate_transactions(
        n_background, start=start, token_service=token_service
    )
    chain = generate_scam_chain(token_service=token_service)
    fanout = generate_scam_fanout(token_service=token_service)
    fanin = generate_scam_fanin(token_service=token_service)
    shop = legitimate_shopkeeper_burst(token_service=token_service)
    txs = sorted(legit + chain + fanout + fanin + shop, key=lambda t: t.timestamp)
    labels: dict[str, str] = {
        "acct_victim_seed": "scam_ring",
        "acct_mule_b1": "mule",
        "acct_mule_w1": "mule",
        "acct_cashout_c1": "mule",
        "acct_fan_origin": "scam_ring",
        "acct_leaf_b1": "mule",
        "acct_leaf_b2": "mule",
        "acct_leaf_w1": "mule",
        "acct_leaf_c1": "mule",
        "acct_leaf_c2": "mule",
        "acct_collector": "scam_ring",
        "acct_cashout_fi": "mule",
        "acct_shop_001": "legit",
    }
    return {
        "name": "mixed_patterns",
        "transactions": txs,
        "labels": labels,
        "meta": {
            "patterns": ["chain", "fanout", "fanin", "shopkeeper_legit"],
            "n_transactions": len(txs),
        },
    }


def all_transactions(scenario: dict[str, Any]) -> list[Transaction]:
    return list(scenario["transactions"])


def scenario_preauth_mule_network(*, seed: int = 7, start: datetime | None = None) -> dict[str, Any]:
    """Deterministic EarlyTrace fixture. Labels are planted by story kind, not by a detector."""
    from app.config import VERSION
    from app.simulator.scam_patterns import (
        GENERATOR_VERSION,
        LABEL_RULE,
        PREAUTH_STORY_KINDS,
        preauth_story_events,
    )

    start = start or datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)
    events = []
    labels: dict[str, dict] = {}
    seq = 1
    for i, kind in enumerate(PREAUTH_STORY_KINDS):
        story_start = start + timedelta(days=i * 3)
        evs, labs, seq = preauth_story_events(kind, seed=seed, start=story_start, seq=seq)
        events.extend(evs)
        labels.update(labs)
    events = sorted(events, key=lambda e: (e.occurred_at, e.event_id))
    manifest = {
        "generator_version": GENERATOR_VERSION,
        "scenario_name": "preauth_mule_network",
        "seed": seed,
        "event_count": len(events),
        "label_generation_rule": LABEL_RULE,
        "split_boundaries": {
            "note": "This scenario is a single ordered stream. Evaluation splits are applied by run_synthetic.",
        },
        "data_status": "synthetic",
        "licence": "repository-generated synthetic events; no third-party dataset",
        "provenance": "Trail simulator stories inspired by documented mule patterns. Not UPI or bank data.",
        "code_version": VERSION,
        "stories": list(PREAUTH_STORY_KINDS),
    }
    return {
        "name": "preauth_mule_network",
        "seed": seed,
        "events": events,
        "labels": labels,
        "manifest": manifest,
    }
