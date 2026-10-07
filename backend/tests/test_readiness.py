"""Safe liveness, readiness, version, and transport metadata tests."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

from app.main import app


def test_healthz_is_liveness_only_and_version_is_safe():
    client = TestClient(app)
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert "audit_chain_intact" not in health.json()

    version = client.get("/version")
    assert version.status_code == 200
    body = version.json()
    assert body["live_integrations"] is False
    assert body["data_status"] == "synthetic"
    assert body["engine_version"] == "earlytrace-b0b1-heuristic-v2"
    assert body["feature_contracts"] == {"b0": "b0.v2", "b1": "motif.v2"}
    assert body["calibration_status"] == "NOT_FITTED"
    assert "TRAIL_MASTER_SECRET" not in version.text
    assert "dev-l1-key" not in version.text


def test_readyz_reports_independent_safe_checks():
    client = TestClient(app)
    response = client.get("/readyz")
    assert response.status_code == 200
    body = response.json()
    assert body["live_integrations"] is False
    assert body["data_status"] == "synthetic"
    assert body["checks"]["legacy_audit"] is True
    assert body["checks"]["paud_store"] is True
    assert body["checks"]["live_integrations_disabled"] is True
    assert "configuration_errors" in body


def test_invalid_request_id_is_replaced_and_security_headers_are_present():
    client = TestClient(app)
    response = client.get("/healthz", headers={"X-Request-Id": "contains spaces and raw\nvalue"})
    assert response.status_code == 200
    assert re.fullmatch(r"[A-Za-z0-9._-]{1,64}", response.headers["X-Request-Id"])
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_default_cors_does_not_allow_an_unconfigured_origin():
    client = TestClient(app)
    response = client.options(
        "/healthz",
        headers={"Origin": "https://unconfigured.example", "Access-Control-Request-Method": "GET"},
    )
    assert response.headers.get("access-control-allow-origin") is None
