from datetime import datetime, timedelta, timezone

from app.context.preauth import ContextFailure, VerifiedContextProvider
from app.models.preauth import EventSource, PreAuthEventV2

NOW = datetime(2026, 6, 1, 10, tzinfo=timezone.utc)


def event(event_id="evt_context1", **changes):
    data = dict(schema_version="earlytrace.preauth.v2", event_id=event_id, occurred_at=NOW,
                as_of=NOW, institution_id="BANK_A", event_source=EventSource.SYNTHETIC_GENERATOR,
                rail="UPI", source_token="tok_" + "1" * 32, payee_token="tok_" + "2" * 32,
                amount_bucket="1k_10k", payee_age_bucket="new", session_context="ROUTINE",
                consent_scope="LOCAL_BEHAVIOUR", trace_id="trace_context", idempotency_key="idem_context1")
    data.update(changes)
    return PreAuthEventV2(**data)


def test_local_consent_matrix_and_server_history():
    provider = VerifiedContextProvider(clock=lambda: NOW)
    current = event()
    prior = event("evt_prior1", occurred_at=NOW - timedelta(minutes=5), as_of=NOW - timedelta(minutes=5))
    provider.register_event(current, history=[prior])
    result = provider.get(current, None, NOW, "LIVE_SYNTHETIC")
    assert result.consent.outcome.value == "VERIFIED_LOCAL"
    assert result.local_sufficient is True
    assert all(item.event_id != current.event_id for item in result.events)


def test_missing_cross_consent_does_not_downgrade_to_local():
    provider = VerifiedContextProvider(clock=lambda: NOW)
    current = event(consent_scope="CONSENTED_BEACON")
    provider.register_event(current, local_authorized=True)
    result = provider.get(current, None, NOW, "LIVE_SYNTHETIC")
    assert result.consent.outcome.value == "MISSING"
    assert result.failure_code == ContextFailure.MISSING_CONSENT
    assert result.local_sufficient is False


def test_future_and_stale_are_server_clock_conditions():
    provider = VerifiedContextProvider(clock=lambda: NOW)
    stale = event(occurred_at=NOW - timedelta(hours=7), as_of=NOW - timedelta(hours=7))
    provider.register_event(stale)
    result = provider.get(stale, None, NOW, "LIVE_SYNTHETIC")
    assert result.local_sufficient is False
    assert result.failure_code == ContextFailure.INSUFFICIENT_EVIDENCE
