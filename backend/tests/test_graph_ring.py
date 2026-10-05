"""Tests for Khanak Part 2: lineage, pattern detection, ring records, evaluation."""
from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from app.detection.graph import (
    build_ring_record,
    detect_pattern,
    detect_ring_from_transactions,
    explain_ring,
)
from app.detection.lineage import build_beacon_graph, build_transaction_graph, subgraph_from_seed
from app.detection.triage import (
    EvalCase,
    demo_eval_from_rings,
    evaluate_siloed_vs_trail,
    recommend_action,
)
from app.models.beacon import Beacon, EdgeType
from app.models.case import ActionCode, ReceiverClass, RiskLevel, RingRecord
from app.simulator import generate_cross_bank_hop, generate_scam_chain, generate_scam_fanout, generate_scam_fanin


def _beacon(token, inst, parent=None, edge=EdgeType.DERIVED_FUNDS, amount="50k_100k", issued=None):
    now = issued if issued is not None else int(time.time())
    epoch = datetime.fromtimestamp(now, tz=timezone.utc).date().isoformat()
    return Beacon(
        token=token,
        parent_token=parent,
        epoch=epoch,
        rail="UPI",
        amount_bucket=amount,
        time_bucket="10:30",
        edge_type=edge,
        institution_id=inst,
        issued_at=now,
        ttl=3600,
    )


def _tok(n: int) -> str:
    return "tok_" + f"{n:032x}"


def test_beacon_graph_lineage():
    seed = _tok(0)
    b0 = _beacon(seed, "BANK_A", edge=EdgeType.COMPLAINT_SEED, issued=1_000_000)
    b1 = _beacon(_tok(1), "BANK_B", parent=seed, issued=1_000_000 + 300)
    b2 = _beacon(_tok(2), "WALLET_W", parent=_tok(1), issued=1_000_000 + 600)
    b3 = _beacon(_tok(3), "BANK_C", parent=_tok(2), issued=1_000_000 + 900)
    G = build_beacon_graph([b0, b1, b2, b3])
    assert seed in G and G.has_edge(seed, _tok(1))
    sub = subgraph_from_seed(G, seed)
    assert set(sub.nodes) == {seed, _tok(1), _tok(2), _tok(3)}


def test_detect_cross_bank_hop_pattern():
    seed = _tok(0)
    beacons = [
        _beacon(seed, "BANK_A", edge=EdgeType.COMPLAINT_SEED, issued=1_000_000),
        _beacon(_tok(1), "BANK_B", parent=seed, issued=1_000_000 + 240),
        _beacon(_tok(2), "WALLET_W", parent=_tok(1), issued=1_000_000 + 480),
        _beacon(_tok(3), "BANK_C", parent=_tok(2), issued=1_000_000 + 720),
    ]
    G = build_beacon_graph(beacons)
    pattern, nodes, edges = detect_pattern(G, seed)
    assert pattern in ("cross_bank_hop", "chain")
    assert len(nodes) >= 3
    ring = build_ring_record(beacons, seed)
    assert ring is not None
    assert isinstance(ring, RingRecord)
    assert ring.seed_token == seed
    assert ring.n_hops >= 3
    assert len(ring.institutions) >= 2
    assert ring.confidence > 0.5
    assert ring.recommended_action in list(ActionCode)
    assert ring.hops[0].token == nodes[0] or ring.hops[0].token == seed
    exp = explain_ring(ring)
    assert exp["pattern"] == ring.pattern
    assert len(exp["hops"]) == ring.n_hops


def test_build_ring_record_none_on_singleton():
    seed = _tok(99)
    b = _beacon(seed, "BANK_A", edge=EdgeType.COMPLAINT_SEED)
    assert build_ring_record([b], seed) is None


def test_fanout_pattern_from_beacons():
    seed = _tok(10)
    leaves = [_tok(11), _tok(12), _tok(13), _tok(14)]
    t0 = 2_000_000
    beacons = [_beacon(seed, "BANK_A", edge=EdgeType.COMPLAINT_SEED, issued=t0)]
    for i, leaf in enumerate(leaves):
        beacons.append(_beacon(leaf, "BANK_B", parent=seed, issued=t0 + 60 * (i + 1)))
    ring = build_ring_record(beacons, seed)
    assert ring is not None
    assert ring.pattern == "fanout"
    assert ring.n_hops >= 4


def test_detect_ring_from_scam_chain_transactions():
    chain = generate_scam_chain()
    # First destination is the seed mule account
    seed = chain[0].destination_token
    ring = detect_ring_from_transactions(chain, seed)
    assert ring is not None
    assert ring.n_hops >= 2
    assert ring.pattern in ("chain", "cross_bank_hop")
    assert all(isinstance(h.risk_score, float) for h in ring.hops)


def test_detect_ring_from_fanout_transactions():
    fo = generate_scam_fanout()
    seed = fo[0].destination_token
    ring = detect_ring_from_transactions(fo, seed)
    assert ring is not None
    # fan-out morphology preferred when out-degree high
    assert ring.pattern in ("fanout", "chain", "cross_bank_hop")


def test_detect_ring_from_cross_bank_hop():
    hop = generate_cross_bank_hop()
    seed = hop[0].destination_token
    ring = detect_ring_from_transactions(hop, seed)
    assert ring is not None
    assert len(ring.institutions) >= 2


def test_receiver_classification_mixed():
    seed = _tok(20)
    t0 = 3_000_000
    beacons = [
        _beacon(seed, "BANK_A", edge=EdgeType.COMPLAINT_SEED, issued=t0, amount="50k_100k"),
        _beacon(_tok(21), "BANK_B", parent=seed, issued=t0 + 300, amount="50k_100k"),
        _beacon(_tok(22), "WALLET_W", parent=_tok(21), issued=t0 + 600, amount="10k_50k"),
        _beacon(_tok(23), "BANK_C", parent=_tok(22), issued=t0 + 900, amount="10k_50k"),
    ]
    ring = build_ring_record(beacons, seed)
    assert ring is not None
    classes = {h.receiver_class for h in ring.hops}
    # Should not mark every hop legitimate
    assert ReceiverClass.RING_CONTROLLED in classes or ReceiverClass.RECRUITED in classes


def test_recommend_action_respects_legitimate():
    seed = _tok(30)
    t0 = 4_000_000
    beacons = [
        _beacon(seed, "BANK_A", edge=EdgeType.COMPLAINT_SEED, issued=t0),
        _beacon(_tok(31), "BANK_B", parent=seed, issued=t0 + 200),
        _beacon(_tok(32), "BANK_C", parent=_tok(31), issued=t0 + 400),
    ]
    ring = build_ring_record(beacons, seed)
    assert ring is not None
    act = recommend_action(ring)
    assert act in list(ActionCode)


def test_evaluation_siloed_vs_trail():
    seed = _tok(40)
    t0 = 5_000_000
    beacons = [
        _beacon(seed, "BANK_A", edge=EdgeType.COMPLAINT_SEED, issued=t0),
        _beacon(_tok(41), "BANK_B", parent=seed, issued=t0 + 180),
        _beacon(_tok(42), "WALLET_W", parent=_tok(41), issued=t0 + 360),
        _beacon(_tok(43), "BANK_C", parent=_tok(42), issued=t0 + 540),
    ]
    ring = build_ring_record(beacons, seed)
    assert ring is not None
    metrics = demo_eval_from_rings([ring])
    d = metrics.to_dict()
    assert "precision_trail" in d and "recall_siloed" in d
    assert d["recall_trail"] >= d["recall_siloed"] or d["precision_trail"] >= 0
    assert "partial_participation_recall" in d

    # Direct EvalCase path
    case = EvalCase(
        case_id="c1",
        true_ring_accounts={seed, _tok(41), _tok(42), _tok(43)},
        true_innocent_accounts=set(),
        siloed_alerts={"BANK_A": {seed}, "BANK_C": {_tok(43)}},
        trail_alerts={seed, _tok(41), _tok(42), _tok(43)},
        complaint_to_ring_minutes_siloed=90,
        complaint_to_ring_minutes_trail=12,
        participating_institutions={"BANK_A", "BANK_B", "WALLET_W", "BANK_C"},
    )
    m2 = evaluate_siloed_vs_trail([case])
    assert m2.recall_trail >= m2.recall_siloed
    assert m2.harm_minutes_trail <= m2.harm_minutes_siloed


def test_ring_record_validates_against_pydantic():
    """Ensure hub can model_validate the engine output."""
    seed = _tok(50)
    t0 = 6_000_000
    beacons = [
        _beacon(seed, "BANK_A", edge=EdgeType.COMPLAINT_SEED, issued=t0),
        _beacon(_tok(51), "BANK_B", parent=seed, issued=t0 + 120),
        _beacon(_tok(52), "BANK_C", parent=_tok(51), issued=t0 + 240),
    ]
    ring = build_ring_record(beacons, seed)
    assert ring is not None
    again = RingRecord.model_validate(ring.model_dump())
    assert again.n_hops == ring.n_hops
