from datetime import datetime, timezone

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.main import app
from app.models.preauth import EventSource, PreAuthEventV2
from app.security.preauth_attestation import PreAuthAttestor
from app.security.rbac import Principal, Role
from app.state import HubState, reset_state


def setup_state():
    now = datetime(2026, 6, 1, 10, tzinfo=timezone.utc)
    st = reset_state(HubState(master_secret=b"tenant-secret-01234567890123456789", clock=lambda: now))
    st.users.register("bank-a-v2", Principal("analyst_a", Role.L1_ANALYST, "BANK_A"))
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    st.context.registry.register("BANK_A", "v1", public, active_at=now, expires_at=now.replace(hour=11))
    event = PreAuthEventV2(schema_version="earlytrace.preauth.v2", event_id="evt_api_v2_1", occurred_at=now, as_of=now,
        institution_id="BANK_A", event_source=EventSource.SYNTHETIC_GENERATOR, rail="UPI", source_token="tok_" + "1" * 32,
        payee_token="tok_" + "2" * 32, amount_bucket="1k_10k", payee_age_bucket="new", session_context="URGENT_SOCIAL_ENGINEERING",
        consent_scope="LOCAL_BEHAVIOUR", trace_id="trace_api_v2", idempotency_key="idem_api_v210")
    st.context.register_event(event, attestation_verified=True, local_authorized=True)
    signed = PreAuthAttestor(st.context.registry, clock=lambda: now).sign_event(event, private, key_version="v1", issued_at=now, expires_at=now.replace(hour=10, minute=5))
    body = {"schema_version": "earlytrace.preauth.v2", "event": {
                "schema_version": "earlytrace.preauth.v2", "event_id": event.event_id,
                "institution_id": event.institution_id, "event_digest": signed.event_digest,
                "trace_id": event.trace_id, "idempotency_key": event.idempotency_key,
            }, "attestation": signed.model_dump(mode="json"), "trace_id": event.trace_id,
            "idempotency_key": event.idempotency_key}
    return st, body


def test_v2_tenant_scoped_decision_and_idempotency():
    st, body = setup_state()
    client = TestClient(app)
    first = client.post("/preauth/decisions", json=body, headers={"X-API-Key": "bank-a-v2"})
    assert first.status_code == 200, first.text
    assert first.json()["engine_version"].endswith("v2")
    again = client.post("/preauth/decisions", json=body, headers={"X-API-Key": "bank-a-v2"})
    assert again.status_code == 200
    assert again.json()["audit_id"] == first.json()["audit_id"]
    assert client.get("/preauth/decisions/evt_api_v2_1", headers={"X-API-Key": "bank-a-v2"}).status_code == 200


def test_v1_http_and_caller_context_are_rejected():
    st, body = setup_state()
    client = TestClient(app)
    old = {"schema_version": "earlytrace.preauth.v1", "event_id": "evt_old001", "occurred_at": "2026-06-01T10:00:00+00:00", "institution_id": "BANK_A", "trace_id": "trace_old1", "idempotency_key": "idem_old001"}
    assert client.post("/preauth/decisions", json=old, headers={"X-API-Key": "bank-a-v2"}).status_code == 410
    body["as_of"] = body["attestation"]["issued_at"]
    assert client.post("/preauth/decisions", json=body, headers={"X-API-Key": "bank-a-v2"}).status_code == 422
