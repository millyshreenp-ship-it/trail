"""Synthetic evaluation harness: splits, abstention, and honest model selection."""
from __future__ import annotations

import json

from app.evaluation.run_synthetic import run_evaluation
from app.models.preauth import DecisionAction


def test_synthetic_evaluation_writes_manifest_and_metrics(tmp_path):
    result = run_evaluation(seed=4, n_days=12, out_dir=tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    metrics = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    assert manifest["data_status"] == "synthetic"
    assert manifest["seed"] == 4
    assert "label_generation_rule" in manifest
    assert metrics["split"] == "temporal"
    assert metrics["neural_model_trained"] is False
    assert metrics["calibrated_runtime"] is False
    assert metrics["conformal_used"] is False
    assert "b0_precision" in metrics["comparison"]
    assert "b1_precision" in metrics["comparison"]
    assert metrics["latency_ms"]["e2e_ms"]["p50"] is not None
    assert (tmp_path / "plots" / "reliability.svg").exists()
    assert result["metrics"]["resources"]["tracemalloc_peak_bytes"] > 0


def test_unknown_action_exists_for_insufficient_evidence():
    assert DecisionAction.UNKNOWN.value == "UNKNOWN"
