from fastapi.testclient import TestClient

from app.main import app
from app.security.rbac import Principal, Role
from tests.test_preauth_tenant import setup_state


def test_workspace_is_tenant_scoped_and_evidence_is_minimized():
    state, submission = setup_state()
    client = TestClient(app)
    headers = {"X-API-Key": "bank-a-v2"}
    assert client.post("/preauth/decisions", json=submission, headers=headers).status_code == 200
    assert client.get("/api/workspace/session", headers=headers).json()["institution"] == "BANK_A"
    items = client.get("/api/workspace/decisions", headers=headers).json()["items"]
    assert len(items) == 1
    event_id = items[0]["event_id"]
    evidence = client.get(f"/api/workspace/decisions/{event_id}/evidence", headers=headers).json()
    assert evidence["excluded_future_events"] is True
    assert all(node["id"].startswith("case_") for node in evidence["nodes"])
    assert "tok_" not in str(evidence)
    state.users.register("workspace-bank-b", Principal("analyst_b", Role.L1_ANALYST, "BANK_B"))
    other = {"X-API-Key": "workspace-bank-b"}
    assert client.get("/api/workspace/decisions", headers=other).json()["items"] == []
    assert client.get(f"/api/workspace/decisions/{event_id}/evidence", headers=other).status_code == 404
    summary = client.get(f"/api/workspace/decisions/{event_id}/summary", headers=headers).json()
    assert summary["authority"] == "read_only"
    assert summary["ai_generated"] is False


def test_workspace_requires_auth_and_bounded_pages():
    setup_state()
    client = TestClient(app)
    assert client.get("/api/workspace/session").status_code == 401
    assert client.get("/api/workspace/decisions?limit=1000", headers={"X-API-Key": "bank-a-v2"}).status_code == 422


def test_assistant_rejects_invented_evidence_and_never_changes_decision(monkeypatch):
    import app.assistance as assistance

    state, submission = setup_state()
    client = TestClient(app)
    headers = {"X-API-Key": "bank-a-v2"}
    decision = client.post("/preauth/decisions", json=submission, headers=headers).json()
    monkeypatch.setenv("TRAIL_ASSISTANT_ENABLED", "1")
    monkeypatch.setenv("TRAIL_ASSISTANT_PROVIDER", "vertex")
    monkeypatch.setattr(assistance, "_vertex", lambda _prompt: '{"summary":"Unsupported allegation","reason_codes":["INVENTED"]}')
    result = assistance.summarize(decision)
    assert result["provider"] == "deterministic"
    assert result["status"] == "provider_unavailable_or_output_rejected"
    assert state.preauth_store.get_decision("BANK_A", decision["event_id"]) == decision
    monkeypatch.setattr(assistance, "_vertex", lambda _prompt: '{"summary":"Verify the recommendation independently.","reason_codes":[]}')
    result = assistance.summarize(decision)
    assert result["ai_generated"] is True
    assert result["authority"] == "read_only"
    assert result["action"] == decision["action"]