"""Tests for Khanak Part 1: simulator, features, local risk scorer."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.detection.features import (
    FEATURE_NAMES,
    compute_account_features,
    compute_features_batch,
    feature_vector,
)
from app.detection.scorer import RiskScorer, default_scorer
from app.models.case import RiskLevel
from app.models.transaction import Transaction
from app.simulator import (
    generate_cross_bank_hop,
    generate_dataset,
    generate_legitimate_transactions,
    generate_scam_chain,
    generate_scam_fanin,
    generate_scam_fanout,
    scenario_north_star,
    write_synthetic_jsonl,
)
from app.simulator.legitimate import legitimate_shopkeeper_burst, legitimate_student_rent


def test_legitimate_generator_scale_and_schema():
    txs = generate_legitimate_transactions(100)
    assert len(txs) == 100
    t = txs[0]
    assert isinstance(t, Transaction)
    assert t.transaction_id
    assert t.rail in ("UPI", "IMPS", "NEFT")
    assert t.amount_bucket in (
        "0_1k", "1k_10k", "10k_50k", "50k_100k", "100k_500k", "500k_plus"
    )
    assert t.source_token and t.destination_token
    assert t.timestamp.tzinfo is not None


def test_scam_chain_rapid_forward():
    chain = generate_scam_chain()
    assert len(chain) >= 3
    # hops should be minutes apart, not days
    for a, b in zip(chain, chain[1:]):
        delta = (b.timestamp - a.timestamp).total_seconds()
        assert 0 < delta <= 15 * 60 + 60  # allow small slack


def test_scam_fanout_and_fanin():
    fo = generate_scam_fanout()
    assert len(fo) >= 5
    origin = fo[0].destination_token
    outs = [t for t in fo[1:] if t.source_token == origin]
    assert len(outs) >= 4

    fi = generate_scam_fanin()
    assert len(fi) >= 4
    collector = fi[0].destination_token
    ins = [t for t in fi if t.destination_token == collector]
    assert len(ins) >= 3


def test_cross_bank_hop_institutions():
    hop = generate_cross_bank_hop()
    insts = {t.destination_institution for t in hop} | {t.source_institution for t in hop}
    assert "BANK_A" in insts and "BANK_B" in insts
    assert "WALLET_W" in insts or "BANK_C" in insts


def test_generate_dataset_meta():
    ds = generate_dataset(n_legitimate=200, n_suspicious=40, seed=1)
    assert ds["meta"]["n_total"] == len(ds["transactions"])
    assert ds["meta"]["n_suspicious"] >= 10
    assert len(ds["rings"]) >= 1
    assert "acct_shop_001" in ds["labels"]


def test_scenario_north_star():
    sc = scenario_north_star(n_background=100)
    assert sc["name"] == "north_star_cross_bank"
    assert any(t.destination_token == "acct_seed_a" for t in sc["transactions"])
    assert sc["labels"]["acct_hop_c"] == "mule"


def test_feature_names_stable():
    assert FEATURE_NAMES == (
        "fwd_ratio_15m",
        "t_fwd_median",
        "in_uniq_senders_1h",
        "out_fan_out_1h",
        "acct_age_days",
        "activity_jump",
    )


def test_features_on_scam_chain_high_forward():
    chain = generate_scam_chain()
    # Score the first mule (receives then quickly forwards)
    mule = chain[0].destination_token
    feats = compute_account_features(chain, mule)
    for name in FEATURE_NAMES:
        assert name in feats
    # Rapid chain ⇒ high forward ratio, low median forward time
    assert feats["fwd_ratio_15m"] >= 0.5
    assert feats["t_fwd_median"] <= 15.0 or feats["t_fwd_median"] >= 900
    vec = feature_vector(feats)
    assert len(vec) == 6


def test_features_on_legit_low_risk_signals():
    rent = legitimate_student_rent()
    # Landlord receives monthly — no rapid forward
    feats = compute_account_features(rent, "acct_landlord_01")
    assert feats["fwd_ratio_15m"] == 0.0
    assert feats["acct_age_days"] >= 0.0


def test_scorer_scam_vs_legit():
    scorer = RiskScorer()
    chain = generate_scam_chain()
    mule = chain[0].destination_token
    scam_result = scorer.score_account(chain, mule)

    rent = legitimate_student_rent()
    legit_result = scorer.score_account(rent, "acct_landlord_01")

    assert 0.0 <= scam_result.risk_score <= 1.0
    assert 0.0 <= legit_result.risk_score <= 1.0
    # Scam mule should score materially higher than quiet landlord
    assert scam_result.risk_score > legit_result.risk_score
    assert scam_result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM)
    assert legit_result.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM)
    assert scam_result.reasons  # non-empty human-readable
    assert "forward" in " ".join(scam_result.reasons).lower() or "beneficiar" in " ".join(scam_result.reasons).lower() or "active" in " ".join(scam_result.reasons).lower()


def test_scorer_fanout_high():
    fo = generate_scam_fanout()
    origin = fo[0].destination_token
    r = default_scorer.score_account(fo, origin)
    assert r.risk_score >= 0.5
    assert r.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_shopkeeper_not_critical_by_default():
    """Legitimate high-volume merchant should not auto-critical on local features alone."""
    shop = legitimate_shopkeeper_burst()
    r = default_scorer.score_account(shop, "acct_shop_001")
    # Fan-in without rapid outward forward → should stay below CRITICAL
    assert r.risk_level != RiskLevel.CRITICAL


def test_risk_result_to_dict():
    r = default_scorer.score({name: 0.0 for name in FEATURE_NAMES})
    d = r.to_dict()
    assert d["risk_level"] == "LOW"
    assert set(d["features"]) == set(FEATURE_NAMES)


def test_write_synthetic_jsonl(tmp_path):
    txs = generate_legitimate_transactions(5)
    path = tmp_path / "sample.jsonl"
    n = write_synthetic_jsonl(path, txs)
    assert n == 5
    assert path.exists()
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 5


def test_batch_features():
    chain = generate_scam_chain()
    accounts = list({t.destination_token for t in chain})
    batch = compute_features_batch(chain, accounts)
    assert set(batch) == set(accounts)
    for feats in batch.values():
        assert set(feats) == set(FEATURE_NAMES)
