import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from app.main import app
from app.security.rbac import Principal, Role
from tests.test_preauth_tenant import setup_state


def test_device_signatures_are_one_time_bound_and_record_only():
    state, submission = setup_state()
    client = TestClient(app)
    headers = {"X-API-Key": "bank-a-v2"}
    decision = client.post("/preauth/decisions", json=submission, headers=headers).json()
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    state.users.register("device-admin", Principal("admin", Role.INSTITUTION_ADMIN, "BANK_A"))
    body = {"device_id": "device_prototype01", "public_key_b64": public}
    assert client.post("/api/workspace/devices", json=body, headers=headers).status_code == 403
    assert client.post("/api/workspace/devices", json=body, headers={"X-API-Key": "device-admin"}).status_code == 200
    challenge = client.post(f"/api/workspace/decisions/{decision['event_id']}/device-challenge", json={"device_id": body["device_id"]}, headers=headers).json()
    message = base64.b64decode(challenge["message_b64"])
    Ed25519PublicKey.from_public_bytes(base64.b64decode(challenge["server_public_key_b64"])).verify(base64.b64decode(challenge["server_signature_b64"]), message)
    signature = base64.b64encode(private.sign(message + b"\nACKNOWLEDGE_REVIEW")).decode()
    path = f"/api/workspace/device-challenges/{challenge['payload']['challenge_id']}/acknowledge"
    assert client.post(path, json={"signature_b64": base64.b64encode(b"x" * 64).decode()}, headers=headers).status_code == 409
    receipt = client.post(path, json={"signature_b64": signature}, headers=headers)
    assert receipt.json()["effect"] == "recorded_only"
    assert client.post(path, json={"signature_b64": signature}, headers=headers).status_code == 409
    assert state.preauth_store.get_decision("BANK_A", decision["event_id"]) == decision
    assert challenge["payload"]["payee_pseudonym"].startswith("case_")


def test_device_revocation_and_expired_challenges_fail_closed():
    from datetime import timedelta
    from app.security.extensions import ExtensionRejected
    import pytest

    state, submission = setup_state()
    client = TestClient(app)
    headers = {"X-API-Key": "bank-a-v2"}
    decision = client.post("/preauth/decisions", json=submission, headers=headers).json()
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    state.extensions.enroll("BANK_A", "device_test_expiry", public)
    challenge = state.extensions.challenge("BANK_A", decision["event_id"], "device_test_expiry")
    signature = base64.b64encode(private.sign(base64.b64decode(challenge["message_b64"]) + b"\nACKNOWLEDGE_REVIEW")).decode()
    state.extensions.revoke("BANK_A", "device_test_expiry")
    with pytest.raises(ExtensionRejected):
        state.extensions.acknowledge("BANK_A", challenge["payload"]["challenge_id"], signature)
    state.extensions.enroll("BANK_A", "device_test_expiry", public)
    now = state.now()
    state.extensions.clock = lambda: now + timedelta(minutes=3)
    with pytest.raises(ExtensionRejected):
        state.extensions.acknowledge("BANK_A", challenge["payload"]["challenge_id"], signature)


def test_checkpoint_is_blinded_tenant_scoped_and_detects_mutation():
    state, submission = setup_state()
    client = TestClient(app)
    headers = {"X-API-Key": "bank-a-v2"}
    client.post("/preauth/decisions", json=submission, headers=headers)
    first = client.post("/api/workspace/checkpoints", headers=headers).json()
    second = client.post("/api/workspace/checkpoints", headers=headers).json()
    assert first["commitment"] != second["commitment"]
    assert "blinding" not in first and "tenant" not in first and "event_id" not in first
    path = f"/api/workspace/checkpoints/{first['checkpoint_id']}/verify"
    assert client.get(path, headers=headers).json()["intact"] is True
    state.users.register("other-bank", Principal("other", Role.L1_ANALYST, "BANK_B"))
    assert client.get(path, headers={"X-API-Key": "other-bank"}).status_code == 409
    state.preauth_store._conn.execute("UPDATE paud_audit SET hash=?", ("0" * 64,))
    assert client.get(path, headers=headers).json()["intact"] is False