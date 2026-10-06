from datetime import datetime, timezone

from app.context.preauth import VerifiedContextProvider
from app.detection.preauth import score_pre_auth_v2
from app.models.preauth import EventSource, PreAuthEventV2


def test_v2_golden_urgent_new_payee_is_step_up():
    now = datetime(2026, 6, 1, 10, tzinfo=timezone.utc)
    event = PreAuthEventV2(schema_version="earlytrace.preauth.v2", event_id="evt_golden1", occurred_at=now, as_of=now,
        institution_id="BANK_A", event_source=EventSource.SYNTHETIC_GENERATOR, rail="UPI",
        source_token="tok_" + "1" * 32, payee_token="tok_" + "2" * 32, amount_bucket="1k_10k",
        payee_age_bucket="new", session_context="URGENT_SOCIAL_ENGINEERING", consent_scope="LOCAL_BEHAVIOUR",
        trace_id="trace_golden", idempotency_key="idem_golden01")
    provider = VerifiedContextProvider(clock=lambda: now)
    provider.register_event(event)
    result = score_pre_auth_v2(event, provider.get(event, None, now, "LIVE_SYNTHETIC"), server_now=now)
    assert result.action.value == "STEP_UP"
    assert result.score_kind.value == "RISK_INDEX"
    assert result.calibrated is False
    assert result.b0_feature_contract == "b0.v2"
    assert result.b1_feature_contract == "motif.v2"
