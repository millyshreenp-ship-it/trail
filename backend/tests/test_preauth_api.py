"""Trusted v2 API, tenant scope, idempotency, and advisory boundaries."""
from fastapi.testclient import TestClient
from app.main import app
from tests.test_preauth_tenant import setup_state


def test_decision_is_durable_idempotent_and_audited():
    st, body = setup_state()
    client = TestClient(app)
    first = client.post("/preauth/decisions", json=body, headers={"X-API-Key": "bank-a-v2"})
    assert first.status_code == 200, first.text
    value = first.json()
    assert value["engine_version"] == "earlytrace-b0b1-heuristic-v2"
    assert value["irreversible"] is False
    assert value["audit_id"].startswith("PAUD-")
    again = client.post("/preauth/decisions", json=body, headers={"X-API-Key": "bank-a-v2"})
    assert again.json()["audit_id"] == value["audit_id"]
    assert any(row["action"] == "PREAUTH_SCORED" for row in st.preauth_store.audit_entries("evt_api_v2_1"))


def test_wrong_tenant_and_unknown_reads_are_generic():
    st, body = setup_state()
    from app.security.rbac import Principal, Role
    st.users.register("bank-b-v2", Principal("analyst_b", Role.L1_ANALYST, "BANK_B"))
    client = TestClient(app)
    assert client.post("/preauth/decisions", json=body, headers={"X-API-Key": "bank-b-v2"}).status_code == 403
    assert client.get("/preauth/decisions/evt_missing1", headers={"X-API-Key": "bank-a-v2"}).json()["detail"] == "not found"


def test_legacy_v1_http_is_retired_and_forbidden_context_never_scores():
    setup_state()
    client = TestClient(app)
    old = {"schema_version": "earlytrace.preauth.v1", "event_id": "evt_old001", "occurred_at": "2026-06-01T10:00:00+00:00", "institution_id": "BANK_A", "trace_id": "trace_old1", "idempotency_key": "idem_old001"}
    assert client.post("/preauth/decisions", json=old, headers={"X-API-Key": "bank-a-v2"}).status_code == 410
    assert client.post("/preauth/freeze", headers={"X-API-Key": "bank-a-v2"}).status_code == 404
    assert client.post("/preauth/report", headers={"X-API-Key": "bank-a-v2"}).status_code == 404


def test_oversized_body_and_retention():
    st, body = setup_state()
    client = TestClient(app)
    assert client.post("/preauth/decisions", content=b"{" + b"a" * 70_000 + b"}", headers={"X-API-Key": "bank-a-v2", "Content-Type": "application/json"}).status_code == 413
    assert client.post("/preauth/decisions", json=body, headers={"X-API-Key": "bank-a-v2"}).status_code == 200
    from datetime import datetime, timedelta, timezone
    st.preauth_store.purge(datetime(2026, 6, 2, 12, tzinfo=timezone.utc))
    assert client.get("/preauth/decisions/evt_api_v2_1", headers={"X-API-Key": "bank-a-v2"}).status_code == 404


def test_readiness_checks_both_ledgers():
    setup_state()
    client = TestClient(app)
    result = client.get("/readyz")
    assert result.status_code == 200
    assert result.json()["preauth_chain_intact"] is True
