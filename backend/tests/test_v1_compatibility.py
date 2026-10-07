"""Regression guard for the audited synthetic v1 evaluator rail."""
from __future__ import annotations

import json
from pathlib import Path

from app.evaluation.run_synthetic import run_evaluation


FIXTURE = Path(__file__).parent / "fixtures" / "earlytrace-v1-seed7.json"


def test_seed7_days24_matches_stable_v1_descriptor(tmp_path):
    expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
    result = run_evaluation(seed=7, n_days=24, out_dir=tmp_path)
    metrics = result["metrics"]
    manifest = result["manifest"]
    assert manifest["data_status"] == expected["data_status"]
    assert manifest["generator_version"] == expected["generator_version"]
    assert metrics["engine_version"] == expected["engine_version"]
    assert metrics["feature_contract"] == expected["feature_contract"]
    assert metrics["n_events"] == expected["event_count"]
    assert metrics["temporal_test"]["n"] == expected["temporal_test_event_count"]
    assert {k: metrics["splits"]["temporal_counts"][k] for k in ("train", "calibration", "test")} == expected["temporal_split_counts"]
    assert metrics["temporal_test"]["b0"]["alert_count"] == expected["budget"]["b0_alert_count"]
    assert metrics["temporal_test"]["b1"]["alert_count"] == expected["budget"]["b1_alert_count"]
    assert metrics["comparison"]["b0_precision"] == expected["budget"]["b0_precision"]
    assert metrics["comparison"]["b1_precision"] == expected["budget"]["b1_precision"]
    assert metrics["temporal_test"]["b0_pr_auc"] == expected["pr_auc"]["b0"]
    assert metrics["temporal_test"]["b1_pr_auc"] == expected["pr_auc"]["b1"]
    assert metrics["lead_time_minutes_mean"] == expected["lead_time_minutes_mean"]
    assert metrics["neural_model_trained"] is False
    assert metrics["calibrated_runtime"] is False
    assert metrics["conformal_used"] is False
