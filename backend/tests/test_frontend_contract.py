"""Static console contract tests for offline safety and API wiring."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HTML = ROOT / "frontend" / "index.html"
REPLAY = ROOT / "frontend" / "earlytrace-replay.json"


def test_console_has_no_runtime_cdn_or_cytoscape_dependency():
    html = HTML.read_text(encoding="utf-8")
    assert "cdnjs.cloudflare.com" not in html
    assert "cytoscape" not in html.lower()
    assert "Local timeline/table view" in html
    assert "OFFLINE SYNTHETIC REPLAY" in html


def test_replay_has_four_non_raw_cases_and_required_safety_copy():
    data = json.loads(REPLAY.read_text(encoding="utf-8"))
    assert data["data_status"] == "synthetic"
    assert data["provenance"] == "earlytrace-sim-1"
    assert {case["id"] for case in data["cases"]} == {
        "merchant_allow", "urgent_new_payee", "rapid_forward_review", "hub_outage_unknown",
    }
    serialized = REPLAY.read_text(encoding="utf-8").lower()
    for forbidden_key in ("account_number", "phone_number", "device_fingerprint", "ip_address", "otp", "mpin"):
        assert forbidden_key not in serialized
    assert all(case["audit_id"] is None for case in data["cases"])
    assert all(case["calibrated"] is False for case in data["cases"])
    assert "legacy complaint / institution-executed workflow" in HTML.read_text(encoding="utf-8").lower()


def test_earlytrace_wires_only_advisory_pre_auth_routes():
    html = HTML.read_text(encoding="utf-8")
    for route in (
        "/preauth/decisions", "/preauth/feedback", "/view", "/display", "/review", "/step-up", "/escalate",
    ):
        assert route in html
    assert "effect=recorded_only" in html
    assert "window.EARLYTRACE_SUBMISSIONS" in html
    assert "No live receipt was invented" in html or "no live receipt was created" in html
