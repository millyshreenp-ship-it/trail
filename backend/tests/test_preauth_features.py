from datetime import datetime, timedelta, timezone

from app.context.preauth import VerifiedContextProvider
from app.detection.features_contract import (
    B0_CONTRACT, MOTIF_CONTRACT, b0_vector_for_event, feature_vector_for_event,
)
from app.models.preauth import EventSource, PreAuthEventV2

NOW = datetime(2026, 6, 1, 10, tzinfo=timezone.utc)


def make(event_id, at, source="1", payee="2"):
    return PreAuthEventV2(schema_version="earlytrace.preauth.v2", event_id=event_id,
        occurred_at=at, as_of=at, institution_id="BANK_A", event_source=EventSource.SYNTHETIC_GENERATOR,
        rail="UPI", source_token="tok_" + source * 32, payee_token="tok_" + payee * 32,
        amount_bucket="1k_10k", payee_age_bucket="new", session_context="ROUTINE",
        consent_scope="LOCAL_BEHAVIOUR", trace_id="trace_feat", idempotency_key="idem_" + event_id[-8:])


def test_current_equal_and_future_events_are_excluded():
    current = make("evt_current1", NOW)
    equal = make("evt_earlier", NOW)
    future = make("evt_future1", NOW + timedelta(minutes=1))
    prior = make("evt_prior01", NOW - timedelta(minutes=1))
    provider = VerifiedContextProvider(clock=lambda: NOW)
    provider.register_event(current, history=[equal, future, prior])
    ctx = provider.get(current, None, NOW, "LIVE_SYNTHETIC")
    vector = feature_vector_for_event(current, ctx, current.occurred_at)
    assert vector.contract == MOTIF_CONTRACT
    # One strict prior is visible; equal/current/future cannot inflate counts.
    assert vector.as_dict()["inbound_count_1h"] == 1.0
    assert b0_vector_for_event(current, ctx, current.occurred_at).contract == B0_CONTRACT


def test_server_time_cannot_expand_feature_as_of():
    current = make("evt_current2", NOW)
    provider = VerifiedContextProvider(clock=lambda: NOW + timedelta(hours=2))
    provider.register_event(current)
    ctx = provider.get(current, None, NOW + timedelta(hours=2), "LIVE_SYNTHETIC")
    try:
        feature_vector_for_event(current, ctx, NOW + timedelta(hours=2))
    except ValueError as exc:
        assert "feature_as_of" in str(exc)
    else:
        raise AssertionError("server receipt time expanded feature boundary")
