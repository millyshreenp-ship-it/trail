"""Contracts, privacy invariants, parallel edges, and stable simulator tokens."""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.detection.graph import build_ring_record
from app.detection.lineage import build_transaction_graph, parallel_edge_data
from app.models.preauth import FORBIDDEN_FIELDS, DecisionAction, PreAuthEvent, walk_forbidden
from app.models.transaction import Transaction
from app.security.tokens import TokenService
from app.simulator.legitimate import SIM_TOKEN_KEY, stable_reference_token


def _event(**overrides):
    base = dict(
        schema_version="earlytrace.preauth.v1",
        event_id="evt_abc123",
        occurred_at=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
        as_of=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
        institution_id="BANK_A",
        rail="UPI",
        source_token="acct_payer_01",
        payee_token="acct_payee_01",
        amount_bucket="1k_10k",
        payee_age_bucket="new",
        session_context="ROUTINE",
        consent_scope="LOCAL_BEHAVIOUR",
        trace_id="trace_abc123",
        idempotency_key="idemabc123",
    )
    base.update(overrides)
    return PreAuthEvent(**base)


def test_event_accepts_minimised_fields():
    event = _event()
    assert event.rail == "UPI"
    assert event.session_context.value == "ROUTINE"


@pytest.mark.parametrize("field", sorted(FORBIDDEN_FIELDS))
def test_forbidden_fields_rejected(field):
    with pytest.raises(ValidationError):
        _event(**{field: "raw-value"})


def test_future_event_rejected():
    with pytest.raises(ValidationError):
        _event(as_of=datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc))


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        _event(occurred_at=datetime(2026, 6, 1, 10, 0), as_of=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc))


def test_decision_actions_have_no_freeze():
    assert "FREEZE" not in {a.value for a in DecisionAction}
    assert DecisionAction.UNKNOWN.value == "UNKNOWN"


def test_walk_forbidden_finds_nested_key():
    assert walk_forbidden({"ok": 1, "nested": {"phone": "1"}}) == ["nested.phone"]


def test_parallel_transactions_are_preserved():
    ts = datetime(2026, 6, 1, tzinfo=timezone.utc)
    def tx(i):
        return Transaction(
            transaction_id=f"tx_{i}", rail="UPI", timestamp=ts,
            source_institution="BANK_A", destination_institution="BANK_B",
            source_token="acct_a", destination_token="acct_b",
            amount_bucket="1k_10k", reference_token="tok_" + "ab" * 16,
            transaction_type="P2P",
        )
    graph = build_transaction_graph([tx(1), tx(2)])
    assert graph.number_of_edges() == 2
    assert len(parallel_edge_data(graph, "acct_a", "acct_b")) == 2
    assert {e["transaction_id"] for e in parallel_edge_data(graph, "acct_a", "acct_b")} == {"tx_1", "tx_2"}


def test_case_scoped_pseudonym_when_case_exists():
    tokens = TokenService(b"unit-test-master-secret-0123456789")
    seed = "tok_" + "11" * 16
    other = "tok_" + "22" * 16
    from app.models.beacon import Beacon, EdgeType
    b0 = Beacon(token=seed, epoch="2026-06-01", rail="UPI", amount_bucket="1k_10k", time_bucket="10:00",
                edge_type=EdgeType.COMPLAINT_SEED, institution_id="BANK_A", issued_at=1_700_000_000)
    b1 = Beacon(token=other, parent_token=seed, epoch="2026-06-01", rail="UPI", amount_bucket="1k_10k",
                time_bucket="10:05", edge_type=EdgeType.DERIVED_FUNDS, institution_id="BANK_B", issued_at=1_700_000_300)
    ring_a = build_ring_record([b0, b1], seed, case_id="TRAIL-1", token_service=tokens)
    ring_b = build_ring_record([b0, b1], seed, case_id="TRAIL-2", token_service=tokens)
    assert ring_a is not None and ring_b is not None
    assert ring_a.hops[0].receiver_pseudonym != ring_b.hops[0].receiver_pseudonym
    assert not ring_a.hops[0].receiver_pseudonym.endswith(seed)
    dumped = ring_a.model_dump(mode="json")
    assert walk_forbidden(dumped) == []


def test_stable_token_matches_across_processes():
    ts = datetime(2026, 6, 1, tzinfo=timezone.utc)
    local = stable_reference_token("UPI", "RRN1", ts, key=SIM_TOKEN_KEY)
    code = (
        "from datetime import datetime, timezone\n"
        "from app.simulator.legitimate import stable_reference_token, SIM_TOKEN_KEY\n"
        "print(stable_reference_token('UPI', 'RRN1', datetime(2026,6,1,tzinfo=timezone.utc), key=SIM_TOKEN_KEY))\n"
    )
    backend = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(backend)
    proc = subprocess.run(
        [sys.executable, "-c", code],
        check=True, capture_output=True, text=True, cwd=backend, env=env,
    )
    assert proc.stdout.strip() == local


def test_different_injected_key_changes_token():
    ts = datetime(2026, 6, 1, tzinfo=timezone.utc)
    assert stable_reference_token("UPI", "RRN1", ts, key=b"k-one-0000000000") != stable_reference_token(
        "UPI", "RRN1", ts, key=b"k-two-0000000000"
    )


def test_generator_order_is_deterministic():
    from app.simulator import generate_legitimate_transactions
    a = generate_legitimate_transactions(30, start=datetime(2026, 9, 1, tzinfo=timezone.utc))
    b = generate_legitimate_transactions(30, start=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert [t.transaction_id for t in a] == [t.transaction_id for t in b]
    assert [t.reference_token for t in a] == [t.reference_token for t in b]
    stamps = [t.timestamp for t in a]
    assert stamps == sorted(stamps)
