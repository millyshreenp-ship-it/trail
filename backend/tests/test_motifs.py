"""Event-time motifs and the B0/B1 policy."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.detection.motifs import build_event_index, extract_motif_features
from app.detection.preauth import PreAuthContext, score_pre_auth
from app.models.preauth import DecisionAction
from app.simulator.scam_patterns import preauth_story_events


T0 = datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)


def _score(kind: str):
    events, labels, _ = preauth_story_events(kind, seed=3, start=T0, seq=1)
    event = events[-1]
    ctx = PreAuthContext(events=events, as_of=event.occurred_at, hub_available=True, expected_institutions=1)
    return score_pre_auth(event, ctx, None), events, labels


def test_merchant_burst_is_not_escalated():
    decision, _, labels = _score("merchant_burst")
    assert labels[decision.event_id]["label"] == 0
    assert decision.action == DecisionAction.ALLOW
    assert decision.calibrated is False
    assert decision.irreversible is False


def test_safe_new_payee_is_warn_not_review():
    decision, _, _ = _score("safe_new_payee")
    assert decision.action == DecisionAction.WARN_AND_VERIFY


def test_urgent_new_beneficiary_steps_up_without_claiming_a_probability():
    events, _, _ = preauth_story_events("new_beneficiary", seed=3, start=T0, seq=1)
    event = events[0]
    decision = score_pre_auth(event, PreAuthContext(events=events, as_of=event.occurred_at), None)
    assert decision.action == DecisionAction.STEP_UP
    assert decision.score is not None
    assert decision.calibrated is False


def test_rapid_forward_requests_analyst_review():
    decision, _, labels = _score("rapid_forward")
    assert labels[decision.event_id]["label"] == 1
    assert decision.action == DecisionAction.ANALYST_REVIEW
    assert any(r.feature == "rapid_forward_ratio" for r in decision.reasons)


def test_household_and_rent_are_not_analyst_review():
    for kind in ("household", "familiar_payment", "pass_through"):
        decision, _, _ = _score(kind)
        assert decision.action != DecisionAction.ANALYST_REVIEW


def test_future_edge_does_not_change_earlier_features():
    events, _, _ = preauth_story_events("rapid_forward", seed=4, start=T0, seq=1)
    early = events[0]
    index_early = build_event_index(events, early.occurred_at)
    feats = extract_motif_features(index_early, early.payee_token, early.occurred_at)
    later = events[1].model_copy(update={
        "occurred_at": early.occurred_at + timedelta(days=2),
        "as_of": early.occurred_at + timedelta(days=2),
    })
    index_with_future = build_event_index([early, later], early.occurred_at)
    again = extract_motif_features(index_with_future, early.payee_token, early.occurred_at)
    assert feats == again
    assert all(e.occurred_at <= early.occurred_at for e in index_early.events)


def test_stale_event_is_unknown():
    events, _, _ = preauth_story_events("safe_new_payee", seed=5, start=T0, seq=1)
    event = events[0]
    decision = score_pre_auth(
        event,
        PreAuthContext(events=[event], as_of=event.occurred_at + timedelta(hours=7)),
        None,
    )
    assert decision.action == DecisionAction.UNKNOWN
    assert decision.score is None


def test_missing_consent_is_unknown():
    events, _, _ = preauth_story_events("safe_new_payee", seed=6, start=T0, seq=1)
    event = events[0].model_copy(update={"consent_scope": "NONE"})
    decision = score_pre_auth(event, PreAuthContext(events=[event], as_of=event.occurred_at), None)
    assert decision.action == DecisionAction.UNKNOWN


def test_hub_outage_stays_local():
    events, _, _ = preauth_story_events("rapid_forward", seed=8, start=T0, seq=1)
    event = events[-1]
    decision = score_pre_auth(
        event,
        PreAuthContext(events=events, as_of=event.occurred_at, hub_available=False),
        optional_beacons=[{"ignored": True}],
    )
    assert decision.participation == "local_only"
    assert decision.action == DecisionAction.ANALYST_REVIEW


def test_partial_institution_does_not_use_hidden_hops():
    events, _, _ = preauth_story_events("partial_visibility", seed=9, start=T0, seq=1)
    visible = [e for e in events if e.institution_id == "BANK_A"]
    event = visible[-1]
    index = build_event_index(events, event.occurred_at, visible_institutions={"BANK_A"})
    assert {e.institution_id for e in index.events} == {"BANK_A"}
    full = extract_motif_features(build_event_index(events, events[-1].occurred_at), events[-1].source_token, events[-1].occurred_at)
    hidden = extract_motif_features(index, event.source_token, event.occurred_at)
    assert full["institution_changes"] >= hidden["institution_changes"]
