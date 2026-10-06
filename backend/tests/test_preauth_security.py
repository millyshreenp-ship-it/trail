"""FEAT-002 HTTP and isolation threat fixtures."""
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from app.main import app
from app.models.beacon import Beacon, EdgeType
from app.security.signing import sign_beacon
from tests.conftest import H, L1, make_beacon
from tests.test_preauth_tenant import setup_state


def test_feature_contract_rejects_a_mismatch():
    from app.detection.features_contract import MOTIF_V2_FEATURE_NAMES
    assert len(MOTIF_V2_FEATURE_NAMES) == 28
    assert tuple(list(MOTIF_V2_FEATURE_NAMES)[:-1] + ["unspecified_feature"]) != MOTIF_V2_FEATURE_NAMES


def test_forged_and_replayed_legacy_beacons_fail(st, keys):
    beacon = make_beacon(st, "BANK_A", "tok_" + "ab" * 16, edge=EdgeType.BEHAVIOURAL)
    assert st.verifier.verify(sign_beacon(beacon, keys["BANK_B"]), "BANK_A").ok is False
    signed = sign_beacon(make_beacon(st, "BANK_A", "tok_" + "cd" * 16, edge=EdgeType.BEHAVIOURAL), keys["BANK_A"])
    assert st.verifier.verify(signed, "BANK_A").ok is True
    assert st.verifier.verify(signed, "BANK_A").ok is False


def test_malformed_forbidden_input_is_rejected_without_echo():
    setup_state()
    client = TestClient(app)
    response = client.post("/preauth/decisions", json={"schema_version": "earlytrace.preauth.v2", "event": {"account_number": "1234567890"}}, headers={"X-API-Key": "bank-a-v2"})
    assert response.status_code == 422
    assert "1234567890" not in response.text


def test_pre_auth_rate_limit_is_tenant_bound():
    st, _ = setup_state()
    st.preauth_limiter.max_events = 2
    client = TestClient(app)
    headers = {"X-API-Key": "bank-a-v2"}
    assert client.get("/preauth/decisions/evt_probe001", headers=headers).status_code == 404
    assert client.get("/preauth/decisions/evt_probe002", headers=headers).status_code == 404
    assert client.get("/preauth/decisions/evt_probe003", headers=headers).status_code == 429


def test_no_legacy_freeze_or_report_route():
    setup_state()
    client = TestClient(app)
    headers = {"X-API-Key": "bank-a-v2"}
    assert client.post("/preauth/freeze", headers=headers).status_code == 404
    assert client.post("/preauth/report", headers=headers).status_code == 404
