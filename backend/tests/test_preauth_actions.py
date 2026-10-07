from tests.test_preauth_tenant import setup_state
from fastapi.testclient import TestClient
from app.main import app


def decision(client):
    _, body = setup_state()
    response = client.post("/preauth/decisions", json=body, headers={"X-API-Key": "bank-a-v2"})
    assert response.status_code == 200, response.text
    return body["event"]["event_id"]


def test_actions_are_strict_idempotent_and_record_only():
    client = TestClient(app)
    event_id = decision(client)
    payload = {"schema_version": "earlytrace.action.v2", "action_id": "act_review01", "event_id": event_id, "action": "REVIEW", "note_code": "REVIEW_RECORDED"}
    first = client.post(f"/preauth/decisions/{event_id}/review", json=payload, headers={"X-API-Key": "bank-a-v2"})
    assert first.status_code == 200, first.text
    assert first.json()["effect"] == "recorded_only"
    again = client.post(f"/preauth/decisions/{event_id}/review", json=payload, headers={"X-API-Key": "bank-a-v2"})
    assert again.status_code == 200
    assert again.json()["duplicate"] is True
    assert client.get(f"/preauth/decisions/{event_id}", headers={"X-API-Key": "bank-a-v2"}).json()["action"] == "STEP_UP"


def test_feedback_is_quarantined_and_does_not_mutate_decision():
    client = TestClient(app)
    event_id = decision(client)
    before = client.get(f"/preauth/decisions/{event_id}", headers={"X-API-Key": "bank-a-v2"}).json()
    payload = {"schema_version": "earlytrace.feedback.v2", "feedback_id": "fb_feedback01", "event_id": event_id, "label": "legitimate"}
    response = client.post("/preauth/feedback", json=payload, headers={"X-API-Key": "bank-a-v2"})
    assert response.status_code == 202
    assert response.json()["applied_to_model"] is False
    after = client.get(f"/preauth/decisions/{event_id}", headers={"X-API-Key": "bank-a-v2"}).json()
    assert (before["action"], before["score"]) == (after["action"], after["score"])
