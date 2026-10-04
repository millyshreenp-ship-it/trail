import json, hashlib

import pytest

from app.config import Settings
from app.security.audit import AuditLog
from app.security.rbac import Role, UserDirectory


def test_audit_log_persists_and_reloads(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    a = AuditLog(path); a.append("u", "l1_analyst", "X", "S1"); a.append("u", "l1_analyst", "Y", "S1")
    b = AuditLog(path)
    assert len(b.entries()) == 2 and b.verify_chain()[0]
    b.append("u", "l1_analyst", "Z", "S1")
    assert AuditLog(path).verify_chain() == (True, None)


def test_tampered_audit_file_refuses_to_load(tmp_path):
    path = tmp_path / "audit.jsonl"
    a = AuditLog(str(path)); a.append("u", "r", "X", "S"); a.append("u", "r", "Y", "S")
    lines = path.read_text().splitlines(); e = json.loads(lines[0]); e["actor"] = "mallory"
    path.write_text(json.dumps(e) + "\n" + lines[1] + "\n")
    with pytest.raises(RuntimeError):
        AuditLog(str(path))


def test_hashed_keys_from_env(monkeypatch):
    digest = hashlib.sha256(b"s3cret").hexdigest()
    monkeypatch.setenv("TRAIL_ENV", "production")
    monkeypatch.setenv("TRAIL_USERS_JSON", json.dumps({digest: {"user_id": "rav", "role": "l2_approver"}}))
    users = UserDirectory()
    assert users.authenticate("s3cret").role == Role.L2_APPROVER
    assert users.authenticate("dev-l1-key") is None and users.authenticate(None) is None


def test_production_config_fails_fast(monkeypatch):
    monkeypatch.setenv("TRAIL_ENV", "production")
    monkeypatch.delenv("TRAIL_USERS_JSON", raising=False)
    with pytest.raises(RuntimeError, match="Unsafe production configuration"):
        Settings().validate()


def test_ops_endpoints_and_headers(client):
    assert client.get("/healthz").json()["status"] == "ok"
    r = client.get("/readyz"); assert r.json()["ready"] is True
    assert r.headers["X-Content-Type-Options"] == "nosniff" and "X-Request-Id" in r.headers
    assert any(a["key"] == "dev-l1-key" for a in client.get("/meta").json()["sandbox_accounts"])
