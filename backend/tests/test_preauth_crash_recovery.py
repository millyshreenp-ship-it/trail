from datetime import datetime, timezone

import pytest

from app.storage.preauth import ReservationLost, SQLiteDecisionStore


def test_reclaimed_reservation_fences_stale_worker():
    now = [datetime(2026, 6, 1, 10, tzinfo=timezone.utc)]
    store = SQLiteDecisionStore(":memory:", clock=lambda: now[0], lease_seconds=1)
    first = store.reserve("BANK_A", "evt_fence1", "idem_fence1", "a" * 64).reservation
    now[0] = now[0].replace(second=2)
    assert store.reclaim_expired() == 1
    second = store.reserve("BANK_A", "evt_fence1", "idem_fence2", "b" * 64).reservation
    with pytest.raises(ReservationLost):
        store.commit_decision(first, {"event_id": "evt_fence1"})
    store.commit_decision(second, {"event_id": "evt_fence1"})
    assert len([row for row in store.audit_entries("evt_fence1") if row["action"] == "PREAUTH_SCORED"]) == 1
