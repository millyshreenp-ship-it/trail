import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.evaluation.run_sim2 import _context_for
from app.research.baselines import B0Baseline, B1Baseline, HGBBaseline
from app.research.calibration import CalibrationArtifact, CalibrationMismatch, fit_platt_artifact
from app.research.manifests import build_candidate_manifest
from app.simulator.sim2 import CorpusConfig, generate_sim2_corpus


ROOT = Path(__file__).resolve().parents[2]


def test_research_baselines_use_v2_contracts_and_hgb_is_offline():
    corpus = generate_sim2_corpus(CorpusConfig(seed=21, story_count=20, calendar_days=45))
    events = corpus["events"]
    contexts = [_context_for(event, events) for event in events]
    assert B0Baseline.metadata.contract == "b0.v2"
    assert B1Baseline.metadata.contract == "motif.v2"
    assert len(B0Baseline().predict(events[:3], contexts[:3])) == 3
    hgb = HGBBaseline().fit(events, contexts, [corpus["truth_by_event"][event.event_id]["label"] for event in events])
    assert hgb.available is True
    assert len(hgb.predict(events[:3], contexts[:3])) == 3


def test_calibration_artifact_fails_closed_on_mismatch():
    metadata = {
        "candidate": "b1-v2",
        "engine_version": "earlytrace-b0b1-heuristic-v2",
        "feature_contract": "motif.v2",
        "feature_hash": "a" * 64,
        "feature_dimension": 28,
        "feature_names": ["f"] * 28,
        "generator_version": "earlytrace-sim-2",
        "event_checksum": "b" * 64,
        "label_checksum": "c" * 64,
        "vector_checksum": "d" * 64,
        "split_checksum": "e" * 64,
        "fit_boundary": "train",
        "calibration_boundary": "calibration",
    }
    artifact = fit_platt_artifact([0.1, 0.2, 0.7, 0.9, 0.3, 0.8, 0.4, 0.6], [0, 0, 1, 1, 0, 1, 0, 1], metadata=metadata)
    payload = artifact.as_dict()
    payload["event_checksum"] = "f" * 64
    with pytest.raises(CalibrationMismatch):
        CalibrationArtifact.from_dict(payload)


def test_candidate_manifest_carries_contract_and_unknown_policy():
    manifest = build_candidate_manifest(
        candidate="test", engine_version="earlytrace-b0b1-heuristic-v2", contract="b0.v2",
        generator_version="earlytrace-sim-2", event_checksum="a" * 64,
        label_checksum="b" * 64, vector_checksum="c" * 64, split_checksum="d" * 64,
        seed=7, unknown_policy="abstain", hyperparameters={"x": 1},
    )
    assert manifest["feature_contract"]["name"] == "b0.v2"
    assert manifest["feature_contract"]["dimension"] == 6
    assert manifest["dependency_lock_hash"] is None
    assert manifest["rmse_policy"].startswith("not_optimized")


def test_api_import_does_not_load_research_package():
    code = "import sys; import app.main; print('app.research' in sys.modules)"
    backend = ROOT / "backend"
    env = dict(__import__("os").environ)
    env["PYTHONPATH"] = str(backend)
    result = subprocess.run([sys.executable, "-c", code], cwd=backend, env=env, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "False"
