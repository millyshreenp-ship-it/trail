from datetime import datetime, timedelta, timezone

from app.storage.preauth import SQLiteDecisionStore


def test_decision_retention_does_not_break_paud_chain(tmp_path):
    now = [datetime(2026, 6, 1, 10, tzinfo=timezone.utc)]
    store = SQLiteDecisionStore(str(tmp_path / "retention.sqlite3"), clock=lambda: now[0])
    reservation = store.reserve("BANK_A", "evt_retention1", "idem_retention1", "a" * 64).reservation
    store.commit_decision(reservation, {"event_id": "evt_retention1", "expires_at": (now[0] + timedelta(minutes=1)).isoformat()})
    now[0] += timedelta(hours=25)
    assert store.purge()["decisions"] == 1
    assert store.get_decision("BANK_A", "evt_retention1") is None
    assert store.verify_chain() == (True, None)
