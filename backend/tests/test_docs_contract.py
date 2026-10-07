"""Documentation status and safety assertions for the eight EarlyTrace docs.

These assertions pin the SAFETY wording the docs must always carry. They were
updated deliberately for the v2 product build: the reported engine is now
``earlytrace-b0b1-heuristic-v2`` and the docs describe the 5-seed benchmark,
the deployed workspace, and the public sandbox demo. The hard rules remain:
synthetic everywhere, uncalibrated risk indices, record-only actions, no DPDP
or production claim, no Kaggle upload, and the key caveats below.
"""
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


def test_all_earlytrace_docs_carry_the_core_safety_wording():
    for name in DOCS:
        text = (ROOT / name).read_text(encoding="utf-8").lower()
        assert "synthetic" in text, name
        # v2 is the reported engine; v1 may still be named as the frozen path.
        assert "earlytrace-b0b1-heuristic-v2" in text, name
        assert "uncalibrated" in text or "not_fitted" in text, name
        # Hard rule: no Kaggle upload.
        assert "no kaggle" in text, name
        # Hard rule: advisory, record-only, no automatic action.
        assert "record-only" in text or "no automatic" in text, name
        # Hard rule: no DPDP, no production claim.
        assert "dpdp" in text, name
        assert "production" in text, name


def test_docs_keep_the_key_caveats():
    text = "\n".join((ROOT / name).read_text(encoding="utf-8").lower() for name in DOCS)
    # The frozen v1 operating point rested on a single alert; keep that caveat.
    assert "one alert" in text
    # Latency numbers are not a service SLO.
    assert "not a loaded" in text or "not a service slo" in text
    # Pseudonymity caveat.
    assert "pseudonymous, not anonymous" in text
    # External dataset rights and checksums remain unresolved.
    assert "rights" in text and "checksum" in text


def test_docs_describe_the_v2_product_build():
    """The refreshed docs must mention the shipped product surfaces."""
    text = "\n".join((ROOT / name).read_text(encoding="utf-8").lower() for name in DOCS)
    assert "workspace" in text
    assert "5-seed" in text or "five-seed" in text or "seeds 7" in text
    assert "cloud run" in text or "staging" in text
