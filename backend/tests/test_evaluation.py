"""Khanak Part 3: simulator ground truth, fan-in fix, evidence-based receiver class, real evaluation."""
from __future__ import annotations

import pytest

from app.detection.evaluation import EvalConfig, run_evaluation
from app.detection.graph import detect_ring_from_transactions
from app.models.case import ReceiverClass
from app.simulator import generate_dataset, scenario_ring_with_legit_receiver


@pytest.fixture(scope="module")
def small():
    return generate_dataset(n_legitimate=1200, n_suspicious=120, seed=5)


def test_dataset_scale_and_unique_ids():
    d = generate_dataset()
    ids = [t.transaction_id for t in d["transactions"]]
    assert len(ids) == len(set(ids)), "transaction_ids must be unique"
    assert d["meta"]["n_suspicious"] >= 500
    assert d["meta"]["n_legitimate"] >= 5000
    assert {m["pattern"] for m in d["ring_meta"]} == {"chain", "fanout", "fanin", "cross_bank_hop"}


def test_dataset_is_reproducible():
    a = generate_dataset(n_legitimate=300, n_suspicious=40, seed=9)["transactions"]
    b = generate_dataset(n_legitimate=300, n_suspicious=40, seed=9)["transactions"]
    assert [t.model_dump() for t in a] == [t.model_dump() for t in b]


def test_lookalike_legit_patterns_present(small):
    types = {t.transaction_type for t in small["transactions"]}
    assert "REFUND" in types
    labels = small["labels"]
    for acct in ("acct_gig_001", "acct_biz_001", "acct_refund_merchant"):
        assert labels[acct] == "legit"


@pytest.mark.parametrize("pattern", ["chain", "fanout", "fanin", "cross_bank_hop"])
def test_every_pattern_recovers_all_members(small, pattern):
    metas = [m for m in small["ring_meta"] if m["pattern"] == pattern]
    assert metas
    for m in metas:
        ring = detect_ring_from_transactions(small["transactions"], m["seed"])
        assert ring is not None
        got = {h.token for h in ring.hops}
        assert set(m["members"]) <= got
        if pattern in ("fanout", "fanin"):
            assert ring.pattern == pattern


def test_fanin_not_triggered_by_busy_merchant_downstream():
    sc = scenario_ring_with_legit_receiver()
    ring = detect_ring_from_transactions(sc["transactions"], sc["meta"]["seed"])
    assert ring.pattern != "fanin"
    assert ring.n_hops == 4  # seed, mule, merchant, settlement — no merchant customers pulled in


def test_legit_receiver_gets_verification_not_hold():
    sc = scenario_ring_with_legit_receiver()
    ring = detect_ring_from_transactions(sc["transactions"], sc["meta"]["seed"])
    by_tok = {h.token: h for h in ring.hops}
    assert by_tok[sc["meta"]["legit_receiver"]].receiver_class == ReceiverClass.LEGITIMATE
    assert by_tok[sc["meta"]["mule"]].receiver_class == ReceiverClass.RING_CONTROLLED
    assert ring.recommended_action.value == "A5"


def test_new_rapid_forwarders_are_not_marked_legitimate(small):
    for m in small["ring_meta"][:20]:
        ring = detect_ring_from_transactions(small["transactions"], m["seed"])
        for h in ring.hops:
            if h.token in m["members"]:
                assert h.receiver_class != ReceiverClass.LEGITIMATE


def test_hops_explain_cross_institution_movement(small):
    m = next(m for m in small["ring_meta"] if m["pattern"] == "cross_bank_hop")
    ring = detect_ring_from_transactions(small["transactions"], m["seed"])
    assert any("Cross-institution movement" in r for h in ring.hops[1:] for r in h.reasons)


def test_trail_beats_siloed_baseline(small):
    rep = run_evaluation(small, EvalConfig(sweep_participation=False))
    assert rep.trail["ring_identified_rate"] >= 0.9
    assert rep.siloed["ring_identified_rate"] < rep.trail["ring_identified_rate"]
    assert rep.trail["harm_minutes_per_ring"] < rep.siloed["harm_minutes_per_ring"]
    assert rep.trail["duplicate_alert_ratio"] <= rep.siloed["duplicate_alert_ratio"]
    full = rep.budgets[max(rep.budgets)]
    assert full["recall_trail"] >= full["recall_siloed"]
    assert full["precision_trail"] >= full["precision_siloed"]


def test_partial_participation_is_monotonic_and_markdown_renders(small):
    rep = run_evaluation(small)
    recalls = [v["recall"] for v in rep.partial_participation.values()]
    assert recalls == sorted(recalls)
    assert recalls[-1] > recalls[0]
    md = rep.to_markdown()
    assert "Trail with partial bank participation" in md and "Assumptions" in md


def test_complaint_rate_limits_trail_coverage(small):
    rep = run_evaluation(small, EvalConfig(complaint_rate=0.3, sweep_participation=False))
    assert rep.n_rings_with_complaint < rep.n_rings


def test_refund_lookalike_is_not_high_risk(small):
    from app.detection.scorer import RiskScorer

    sc = RiskScorer()
    res = sc.score_account(small["transactions"], "acct_refund_merchant")
    assert res.risk_level.value in ("LOW", "MEDIUM")
    assert res.features["round_trip_ratio"] >= 0.5


def test_round_trip_does_not_discount_real_mules(small):
    from app.detection.scorer import RiskScorer

    sc = RiskScorer()
    mule = next(m for m in small["ring_meta"] if m["pattern"] == "chain")["members"][1]
    assert sc.score_account(small["transactions"], mule).risk_level.value in ("HIGH", "CRITICAL")
