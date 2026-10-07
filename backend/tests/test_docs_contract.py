"""Documentation status and safety assertions for the eight EarlyTrace docs."""
from __future__ import annotations

from pathlib import Path


DOCS = (
    "earlytrace-scope.md",
    "data-manifest.md",
    "model-card-earlytrace.md",
    "evaluation-protocol.md",
    "demo-runbook.md",
    "pitch-outline.md",
    "architecture-outline.md",
    "implementation-status.md",
)
ROOT = Path(__file__).resolve().parents[2] / "docs"


def test_all_earlytrace_docs_distinguish_v1_from_pending_v2():
    for name in DOCS:
        text = (ROOT / name).read_text(encoding="utf-8").lower()
        assert "synthetic" in text, name
        assert "earlytrace-b0b1-heuristic-v1" in text, name
        assert "uncalibrated" in text or "not_fitted" in text, name
        assert "no kaggle" in text, name
        assert "no automatic" in text or "record-only" in text, name
        assert "dpdp" in text, name
        assert "production" in text, name


def test_docs_keep_the_one_alert_and_latency_caveats():
    text = "\n".join((ROOT / name).read_text(encoding="utf-8").lower() for name in DOCS)
    assert "one alert" in text
    assert "not a loaded" in text or "not a service slo" in text
    assert "pseudonymous, not anonymous" in text
    assert "rights" in text and "checksum" in text
