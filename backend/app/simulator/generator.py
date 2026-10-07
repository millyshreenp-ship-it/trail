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
from datetime import datetime, timedelta, timezone
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
from app.simulator.scenarios import scenario_mixed_patterns, scenario_north_star, scenario_preauth_mule_network
from app.simulator.sim2 import (
    CorpusConfig,
    generate_preauth_corpus_v2,
    generate_sim2_corpus,
    generate_story_corpus,
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
    "scenario_preauth_mule_network",
    "generate_preauth_corpus",
    "CorpusConfig",
    "generate_sim2_corpus",
    "generate_preauth_corpus_v2",
    "generate_story_corpus",
    "write_manifest",
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

    all_txs = sorted(legit + shop + rent + suspicious, key=lambda t: (t.timestamp, t.transaction_id))
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


def generate_preauth_corpus(
    *,
    seed: int = 7,
    n_days: int = 36,
    stories_per_day: int = 1,
    config=None,
    story_count: int | None = None,
    volume_target: int | None = None,
    calendar_days: int | None = None,
    institutions: tuple[str, ...] = ("BANK_A", "BANK_B", "BANK_C"),
    scenario_mixture=None,
    mixture=None,
    held_out_morphology: str | None = None,
) -> dict[str, Any]:
    """Generate the frozen v1 corpus unless an explicit sim-2 control is used.

    The legacy positional shape remains unchanged. Supplying ``config`` or a
    sim-2 control makes the versioned story path explicit.
    """
    if config is not None or any(value is not None for value in (story_count, volume_target, calendar_days, scenario_mixture, mixture)):
        from app.simulator.sim2 import DEFAULT_SCENARIO_MIXTURE, CorpusConfig, generate_sim2_corpus
        selected_config = config or CorpusConfig(
            seed=seed,
            calendar_days=calendar_days if calendar_days is not None else n_days,
            story_count=story_count if volume_target is None else None,
            volume_target=volume_target,
            institutions=institutions,
            scenario_mixture=scenario_mixture if scenario_mixture is not None else (mixture if mixture is not None else DEFAULT_SCENARIO_MIXTURE),
            held_out_morphology=held_out_morphology if held_out_morphology is not None else "split_value",
        )
        return generate_sim2_corpus(selected_config)
    from app.config import VERSION
    from app.simulator.scam_patterns import GENERATOR_VERSION, LABEL_RULE, PREAUTH_STORY_KINDS, preauth_story_events

    rng = random.Random(seed)
    origin = datetime(2026, 5, 1, 8, 0, tzinfo=timezone.utc)
    events = []
    labels: dict[str, dict] = {}
    seq = 1
    for day in range(n_days):
        for _k in range(stories_per_day):
            kind = PREAUTH_STORY_KINDS[rng.randrange(len(PREAUTH_STORY_KINDS))]
            story_seed = rng.randrange(1, 9000)
            start = origin + timedelta(days=day, minutes=rng.randrange(0, 600))
            evs, labs, seq = preauth_story_events(kind, seed=story_seed, start=start, seq=seq)
            events.extend(evs)
            labels.update(labs)
    events = sorted(events, key=lambda e: (e.occurred_at, e.event_id))
    train_end = origin + timedelta(days=int(n_days * 0.6))
    cal_end = origin + timedelta(days=int(n_days * 0.8))
    manifest = {
        "generator_version": GENERATOR_VERSION,
        "scenario_name": "preauth_corpus",
        "seed": seed,
        "event_count": len(events),
        "label_generation_rule": LABEL_RULE,
        "split_boundaries": {
            "origin": origin.isoformat(),
            "train_end": train_end.isoformat(),
            "calibration_end": cal_end.isoformat(),
            "test_end": (origin + timedelta(days=n_days)).isoformat(),
            "scheme": "temporal: train < train_end <= calibration < calibration_end <= test",
        },
        "data_status": "synthetic",
        "licence": "repository-generated synthetic events; no third-party dataset",
        "provenance": "Synthetic payment-event simulator. Not customer, UPI, or bank data.",
        "code_version": VERSION,
        "n_days": n_days,
    }
    return {"name": "preauth_corpus", "seed": seed, "events": events, "labels": labels, "manifest": manifest}


def write_manifest(path: str | Path, manifest: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


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
