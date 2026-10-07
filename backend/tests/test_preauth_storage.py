from datetime import datetime, timedelta, timezone

import pytest

from app.storage.preauth import SQLiteDecisionStore, StoreConflict

NOW = datetime(2026, 6, 1, 10, tzinfo=timezone.utc)


def test_sqlite_reservation_commit_idempotency_and_chain(tmp_path):
    path = str(tmp_path / "preauth.sqlite3")
    store = SQLiteDecisionStore(path, clock=lambda: NOW)
    reservation = store.reserve("BANK_A", "evt_store1", "idem_store1", "a" * 64).reservation
    decision = {"event_id": "evt_store1", "action": "ALLOW", "expires_at": (NOW + timedelta(minutes=15)).isoformat()}
    committed = store.commit_decision(reservation, decision)
    assert committed["audit_id"].startswith("PAUD-")
    replay = store.reserve("BANK_A", "evt_store1", "idem_store1", "a" * 64)
    assert replay.duplicate is True
    assert replay.decision["audit_id"] == committed["audit_id"]
    with pytest.raises(StoreConflict):
        store.reserve("BANK_A", "evt_store1", "idem_store1", "b" * 64)
    assert store.verify_chain() == (True, None)
    reopened = SQLiteDecisionStore(path, clock=lambda: NOW)
    assert reopened.get_decision("BANK_A", "evt_store1")["action"] == "ALLOW"
    assert reopened.verify_chain() == (True, None)


def test_tenant_keys_are_isolated(tmp_path):
    store = SQLiteDecisionStore(str(tmp_path / "tenant.sqlite3"), clock=lambda: NOW)
    reservation = store.reserve("BANK_A", "evt_same1", "idem_same1", "a" * 64).reservation
    store.commit_decision(reservation, {"event_id": "evt_same1", "expires_at": (NOW + timedelta(minutes=1)).isoformat()})
    assert store.get_decision("BANK_B", "evt_same1") is None
