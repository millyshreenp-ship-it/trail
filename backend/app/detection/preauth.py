"""Deterministic B0/B1 pre-authorisation scorer.

B0 is Trail's six-feature heuristic. B1 is the temporal-motif table.
The numeric score is an uncalibrated risk score until a time-separated
calibration artifact is supplied and its feature contract matches.
Actions are advisory. This module has no freeze, reversal, or report path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.detection.features import compute_account_features
from app.detection.motifs import EventIndex, build_event_index, extract_motif_features
from app.detection.scorer import RiskScorer
from app.models.preauth import (
    ConsentScope,
    DecisionAction,
    DecisionReason,
    EvidenceItem,
    LocalSignalFlags,
    PayeeAgeBucket,
    PreAuthEvent,
    RiskBand,
    RiskDecision,
    SessionContext,
)
from app.models.transaction import Transaction

ENGINE_VERSION = "earlytrace-b0b1-heuristic-v1"
STALE_SECONDS = 6 * 3600
FEATURE_CONTRACT = "motif.v1"


@dataclass
class PreAuthContext:
    events: list = field(default_factory=list)
    as_of: datetime | None = None
    hub_available: bool = True
    participating_institutions: list[str] | None = None
    expected_institutions: int = 1


def _aware(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _band(action: DecisionAction) -> RiskBand:
    if action == DecisionAction.UNKNOWN:
        return RiskBand.UNKNOWN
    if action == DecisionAction.ANALYST_REVIEW:
        return RiskBand.HIGH
    if action in (DecisionAction.STEP_UP, DecisionAction.WARN_AND_VERIFY):
        return RiskBand.ELEVATED
    return RiskBand.LOW


def _reason(code: str, feature: str, template: str, value: float | str | None = None) -> DecisionReason:
    return DecisionReason(code=code, feature=feature, template=template, value=value)


def events_to_transactions(events: list[PreAuthEvent]) -> list[Transaction]:
    """Adapt pre-auth events to Trail transactions for the B0 heuristic."""
    out: list[Transaction] = []
    for e in events:
        kind = "P2M" if e.session_context == SessionContext.MERCHANT_CHECKOUT else "P2P"
        out.append(
            Transaction(
                transaction_id=e.event_id,
                rail=e.rail,
                timestamp=e.occurred_at,
                source_institution=e.institution_id,
                destination_institution=e.institution_id,
                source_token=e.source_token,
                destination_token=e.payee_token,
                amount_bucket=e.amount_bucket,
                reference_token="tok_" + "0" * 32,
                device_token=None,
                merchant_category="grocery" if kind == "P2M" else None,
                transaction_type=kind,
            )
        )
    return out


def _b0_score(transactions: list[Transaction], token: str, as_of: datetime) -> float | None:
    if not transactions:
        return None
    feats = compute_account_features(transactions, token, as_of=as_of)
    if sum(feats.values()) == 0.0:
        return None
    return RiskScorer().score(feats).risk_score


def motif_score(features: dict[str, float]) -> float:
    score = 0.0
    score += 0.34 * features.get("rapid_forward_ratio", 0.0)
    score += 0.16 * features.get("payee_age_new", 0.0)
    score += 0.14 * features.get("urgent_context", 0.0)
    score += 0.10 * min(1.0, features.get("fan_out", 0.0) / 4.0)
    score += 0.06 * min(1.0, features.get("fan_in", 0.0) / 4.0)
    score += 0.06 * features.get("dormant_burst", 0.0)
    score += 0.06 * features.get("structuring", 0.0)
    score += 0.04 * min(1.0, features.get("institution_changes", 0.0) / 3.0)
    score += 0.04 * features.get("delayed_hop", 0.0)
    return round(max(0.0, min(1.0, score)), 4)


def _visible_institutions(event: PreAuthEvent, context: PreAuthContext) -> set[str] | None:
    if event.consent_scope == ConsentScope.NONE:
        return {event.institution_id}
    if event.consent_scope == ConsentScope.LOCAL_BEHAVIOUR or not context.hub_available:
        return {event.institution_id}
    if context.participating_institutions:
        return set(context.participating_institutions) | {event.institution_id}
    return None


def _participation_label(ratio: float, hub_available: bool) -> str:
    if not hub_available:
        return "local_only"
    if ratio >= 0.99:
        return "full"
    if ratio > 0:
        return "partial"
    return "none"


def _apply_policy(features: dict[str, float], blend: float, *, partial: bool) -> tuple[DecisionAction, list[DecisionReason], float]:
    reasons: list[DecisionReason] = []
    rapid = features.get("rapid_forward_ratio", 0.0)
    protected = False

    if features.get("merchant_fanin", 0.0) >= 1 and rapid < 0.2:
        protected = True
        reasons.append(_reason("R_MERCHANT_FANIN", "merchant_fanin", "Inbound pattern matches a merchant checkout burst"))
    elif features.get("recurring_pair", 0.0) >= 1 and rapid < 0.2:
        protected = True
        reasons.append(_reason("R_RECURRING_PAIR", "recurring_pair", "Repeated counterparty over long gaps, without rapid forwarding"))
    elif features.get("refund_like", 0.0) >= 1:
        protected = True
        reasons.append(_reason("R_REFUND_LIKE", "refund_like", "Reverse payment between the same parties inside a week"))
    elif features.get("household_like", 0.0) >= 1:
        protected = True
        reasons.append(_reason("R_HOUSEHOLD", "household_like", "Small repeated inflows without rapid onward movement"))

    if protected:
        return DecisionAction.ALLOW, reasons, min(blend, 0.2)

    if rapid >= 0.5:
        reasons.append(_reason("R_RAPID_FORWARD", "rapid_forward_ratio", "Inbound value forwarded within 15 minutes", round(rapid, 4)))
    if features.get("structuring", 0.0) >= 1:
        reasons.append(_reason("R_STRUCTURING", "structuring", "Repeated same-bucket outbound payments in a short window"))
    if features.get("fan_out", 0.0) >= 3:
        reasons.append(_reason("R_FAN_OUT", "fan_out", "Several distinct payees in the last hour", features["fan_out"]))
    if features.get("fan_in", 0.0) >= 3 and rapid >= 0.5:
        reasons.append(_reason("R_FAN_IN", "fan_in", "Several distinct senders followed by rapid forwarding", features["fan_in"]))
    if features.get("delayed_hop", 0.0) >= 1:
        reasons.append(_reason("R_DELAYED_HOP", "delayed_hop_gap_min", "Onward payment after a multi-hour gap", features.get("delayed_hop_gap_min")))
    if features.get("urgent_context", 0.0) >= 1 and features.get("payee_age_new", 0.0) >= 1:
        reasons.append(_reason(
            "R_URGENT_NEW_PAYEE", "urgent_context",
            "Urgent new-beneficiary context. This is a prompt to verify, not a finding of fraud",
        ))
    elif features.get("new_payee_no_onward", 0.0) >= 1:
        reasons.append(_reason("R_NEW_PAYEE", "new_payee_no_onward", "New payee with no onward movement in the visible window"))

    action = DecisionAction.ALLOW
    if rapid >= 0.5 or features.get("structuring", 0.0) >= 1 or (
        features.get("fan_out", 0.0) >= 3 and features.get("payee_age_new", 0.0) >= 1
    ):
        action = DecisionAction.ANALYST_REVIEW
    elif features.get("delayed_hop", 0.0) >= 1:
        action = DecisionAction.STEP_UP
    elif features.get("urgent_context", 0.0) >= 1 and features.get("payee_age_new", 0.0) >= 1:
        action = DecisionAction.STEP_UP
    elif features.get("new_payee_no_onward", 0.0) >= 1:
        action = DecisionAction.WARN_AND_VERIFY
    elif blend >= 0.72:
        action = DecisionAction.ANALYST_REVIEW
    elif blend >= 0.55:
        action = DecisionAction.STEP_UP
    elif blend >= 0.32:
        action = DecisionAction.WARN_AND_VERIFY

    if partial and action == DecisionAction.ANALYST_REVIEW and rapid < 0.5:
        action = DecisionAction.STEP_UP
        reasons.append(_reason(
            "R_PARTIAL_VIEW", "participation_ratio",
            "Only part of the institution set is visible, so the action stays at step-up",
        ))
    if not reasons:
        reasons.append(_reason("R_NO_STRONG_MOTIF", "motif_score", "No strong temporal motif in the visible window"))
    return action, reasons, blend


def score_pre_auth(event: PreAuthEvent, context: PreAuthContext, optional_beacons=None) -> RiskDecision:
    """Score one pre-authorisation event. optional_beacons are ignored when the hub is down."""
    as_of = _aware(context.as_of or event.as_of)
    flags = LocalSignalFlags(
        new_beneficiary=event.payee_age_bucket == PayeeAgeBucket.NEW
        or event.session_context == SessionContext.NEW_BENEFICIARY,
        urgent_context=event.session_context == SessionContext.URGENT_SOCIAL_ENGINEERING,
        hub_unavailable=not context.hub_available,
    )

    def _unknown(reason: str, coverage: float = 0.0, participation: str = "none") -> RiskDecision:
        return RiskDecision(
            event_id=event.event_id,
            trace_id=event.trace_id,
            as_of=as_of,
            action=DecisionAction.UNKNOWN,
            risk_band=RiskBand.UNKNOWN,
            score=None,
            calibrated=False,
            reasons=[_reason("R_INSUFFICIENT", "coverage", reason)],
            evidence=[],
            coverage=coverage,
            participation=participation,  # type: ignore[arg-type]
            unknown_reason=reason,
            engine_version=ENGINE_VERSION,
            expires_at=as_of + timedelta(hours=1),
        )

    if event.consent_scope == ConsentScope.NONE:
        return _unknown("Consent scope is none, so behavioural history was not used")

    age_s = (as_of - _aware(event.occurred_at)).total_seconds()
    if age_s > STALE_SECONDS:
        flags.evidence_stale = True
        decision = _unknown("Event is older than the 6 hour evidence window", participation="local_only")
        return decision

    if event.payee_age_bucket == PayeeAgeBucket.UNKNOWN and event.session_context == SessionContext.ROUTINE:
        history = [e for e in context.events if _aware(e.occurred_at) <= as_of]
        if len(history) <= 1:
            return _unknown("Payee age is unknown and there is no usable local history")

    visible = _visible_institutions(event, context)
    stream = list(context.events)
    if event not in stream and all(getattr(e, "event_id", None) != event.event_id for e in stream):
        stream.append(event)
    index: EventIndex = build_event_index(stream, as_of, visible_institutions=visible)
    expected = max(1, context.expected_institutions)
    payee_f = extract_motif_features(
        index, event.payee_token, as_of, expected_institutions=expected,
    )
    source_f = extract_motif_features(
        index, event.source_token, as_of, expected_institutions=expected,
    )
    # The payee carries mule-movement motifs. The source carries the new-payee context
    # when the current event is the only observation of that payee.
    features = dict(payee_f)
    for key in ("payee_age_new", "urgent_context", "new_payee_no_onward"):
        features[key] = max(payee_f.get(key, 0.0), source_f.get(key, 0.0))
    if event.payee_age_bucket == PayeeAgeBucket.NEW:
        features["payee_age_new"] = 1.0
    if event.session_context == SessionContext.URGENT_SOCIAL_ENGINEERING:
        features["urgent_context"] = 1.0
    if event.payee_age_bucket == PayeeAgeBucket.NEW and payee_f.get("outbound_count_24h", 0) == 0 and source_f.get("rapid_forward_ratio", 0) < 0.5:
        # No onward movement from the payee yet.
        if payee_f.get("outbound_count_1h", 0) == 0 and payee_f.get("inbound_count_24h", 0) <= 1:
            features["new_payee_no_onward"] = 1.0
    features["rapid_forward_ratio"] = max(payee_f.get("rapid_forward_ratio", 0.0), source_f.get("rapid_forward_ratio", 0.0))
    features["fan_out"] = max(payee_f.get("fan_out", 0.0), source_f.get("fan_out", 0.0))
    features["structuring"] = max(payee_f.get("structuring", 0.0), source_f.get("structuring", 0.0))
    features["delayed_hop"] = max(payee_f.get("delayed_hop", 0.0), source_f.get("delayed_hop", 0.0))
    features["merchant_fanin"] = max(payee_f.get("merchant_fanin", 0.0), source_f.get("merchant_fanin", 0.0))
    features["recurring_pair"] = max(payee_f.get("recurring_pair", 0.0), source_f.get("recurring_pair", 0.0))
    features["household_like"] = max(payee_f.get("household_like", 0.0), source_f.get("household_like", 0.0))
    features["refund_like"] = max(payee_f.get("refund_like", 0.0), source_f.get("refund_like", 0.0))

    b1 = motif_score(features)
    txs = events_to_transactions([e for e in stream if _aware(e.occurred_at) <= as_of])
    if visible is not None:
        txs = [t for t in txs if t.source_institution in visible]
    b0_payee = _b0_score(txs, event.payee_token, as_of)
    b0_source = _b0_score(txs, event.source_token, as_of)
    b0_vals = [v for v in (b0_payee, b0_source) if v is not None]
    b0 = max(b0_vals) if b0_vals else None
    blend = b1 if b0 is None else round(0.45 * b0 + 0.55 * b1, 4)

    ratio = max(payee_f.get("participation_ratio", 0.0), source_f.get("participation_ratio", 0.0))
    partial = (not context.hub_available) or ratio < 0.5
    flags.partial_participation = partial
    flags.rapid_forward_observed = features.get("rapid_forward_ratio", 0.0) >= 0.5
    action, reasons, blend = _apply_policy(features, blend, partial=partial and context.expected_institutions > 1)

    if b0 is not None:
        reasons.append(_reason("R_B0_HEURISTIC", "b0_score", "Trail six-feature heuristic on visible events", b0))
    reasons.append(_reason("R_B1_MOTIF", "motif_score", "Uncalibrated temporal-motif score", b1))

    coverage = max(payee_f.get("evidence_coverage", 0.0), source_f.get("evidence_coverage", 0.0))
    if optional_beacons and context.hub_available and event.consent_scope == ConsentScope.CONSENTED_BEACON:
        reasons.append(_reason("R_BEACON_AVAILABLE", "beacons", "Optional signed beacons were supplied and not required"))
    elif not context.hub_available:
        reasons.append(_reason("R_HUB_UNAVAILABLE", "hub_available", "Hub corroboration is unavailable; decision uses local events only"))

    participation = _participation_label(ratio if context.hub_available else 0.0, context.hub_available)
    if not context.hub_available:
        participation = "local_only"

    evidence = [
        EvidenceItem(
            evidence_id="ev_" + event.event_id.replace("evt_", "")[:60],
            kind="motif",
            observed_at=event.occurred_at,
            expires_at=as_of + timedelta(hours=6),
            institution_id=event.institution_id,
            coverage=coverage,
            fresh=True,
        )
    ]
    return RiskDecision(
        event_id=event.event_id,
        trace_id=event.trace_id,
        as_of=as_of,
        action=action,
        risk_band=_band(action),
        score=round(blend, 4),
        calibrated=False,
        reasons=reasons,
        evidence=evidence,
        coverage=coverage,
        participation=participation,  # type: ignore[arg-type]
        unknown_reason=None,
        engine_version=ENGINE_VERSION,
        expires_at=as_of + timedelta(minutes=15 if action != DecisionAction.ANALYST_REVIEW else 60),
    )


# ---------------------------------------------------------------------------
# v2 runtime.  The functions above remain the frozen v1 compatibility rail.
from app.context.preauth import ContextFailure, ContextResult
from app.detection.features_contract import (
    B0_CONTRACT, B0_FEATURE_HASH, MOTIF_CONTRACT, MOTIF_FEATURE_HASH,
    b0_risk_index, b0_vector_for_event, b1_risk_index, feature_vector_for_event,
)
from app.models.preauth import (
    CalibrationStatus, ConsentOutcome, DecisionReasonV2, EvidenceItemV2,
    EvidenceKind, EvidenceSummaryCode, Participation, RiskBand, RiskDecisionV2,
    ScoreKind, UnknownReason, UncertaintySummary,
)

V2_ENGINE_VERSION = "earlytrace-b0b1-heuristic-v2"


def _v2_band(action: DecisionAction) -> RiskBand:
    if action == DecisionAction.UNKNOWN:
        return RiskBand.UNKNOWN
    if action == DecisionAction.ANALYST_REVIEW:
        return RiskBand.HIGH
    if action in (DecisionAction.STEP_UP, DecisionAction.WARN_AND_VERIFY):
        return RiskBand.ELEVATED
    return RiskBand.LOW


def _v2_unknown_reason(failure: ContextFailure | str | None) -> UnknownReason:
    value = getattr(failure, "value", failure)
    return {
        "MISSING_CONSENT": UnknownReason.MISSING_CONSENT,
        "INVALID_CONSENT": UnknownReason.MISSING_CONSENT,
        "EXPIRED_CONSENT": UnknownReason.MISSING_CONSENT,
        "REVOKED_CONSENT": UnknownReason.MISSING_CONSENT,
        "CONTEXT_CONFLICT": UnknownReason.CONTEXT_CONFLICT,
        "CONTEXT_UNAVAILABLE": UnknownReason.CONTEXT_UNAVAILABLE,
        "INSUFFICIENT_HISTORY": UnknownReason.INSUFFICIENT_HISTORY,
        "INSUFFICIENT_EVIDENCE": UnknownReason.INSUFFICIENT_EVIDENCE,
    }.get(value, UnknownReason.INSUFFICIENT_EVIDENCE)


def _uncertainty(coverage: float, participation: Participation, *, unknown: bool = False) -> UncertaintySummary:
    ratio = {Participation.NONE: 0.0, Participation.LOCAL_ONLY: 0.25, Participation.PARTIAL: 0.5, Participation.FULL: 1.0}[participation]
    amount = round(max(0.0, min(1.0, 1 - (0.60 * coverage + 0.40 * ratio))), 4)
    level = "HIGH" if unknown or amount > 0.50 else "MEDIUM" if amount > 0.25 else "LOW"
    return UncertaintySummary(level=level, reasons=[])


def _v2_reason(code: str, feature: str, value=None) -> DecisionReasonV2:
    return DecisionReasonV2(code=code, feature=feature, value=value, template_id=code.lower())


def _v2_unknown(event, now: datetime, context: ContextResult, reason: UnknownReason) -> RiskDecisionV2:
    return RiskDecisionV2(
        event_id=event.event_id, trace_id=event.trace_id, as_of=now,
        subject_event_time=event.occurred_at, execution_mode="LIVE_SYNTHETIC",
        action=DecisionAction.UNKNOWN, risk_band=RiskBand.UNKNOWN, score=None,
        score_kind=ScoreKind.NONE, calibrated=False, reasons=[_v2_reason("R_INSUFFICIENT", "coverage")], evidence=[],
        evidence_coverage=context.evidence_coverage, participation=context.participation.participation,
        local_only=context.participation.local_only, consent_outcome=context.consent.outcome,
        uncertainty=_uncertainty(context.evidence_coverage, context.participation.participation, unknown=True),
        engine_version=V2_ENGINE_VERSION, b0_feature_contract="none", b0_feature_hash="0" * 64,
        b1_feature_contract="none", b1_feature_hash="0" * 64, calibration_status=CalibrationStatus.UNAVAILABLE,
        unknown_reason=reason, expires_at=now + timedelta(minutes=15),
    )


def score_pre_auth_v2(event, context: ContextResult, *, server_now: datetime, execution_mode="LIVE_SYNTHETIC") -> RiskDecisionV2:
    """Score trusted context only; caller-owned history/context never reaches here."""
    now = _aware(server_now)
    failure = context.failure_code
    if failure != ContextFailure.NONE or not context.local_sufficient:
        return _v2_unknown(event, now, context, _v2_unknown_reason(failure))
    b0v = b0_vector_for_event(event, context, event.occurred_at)
    b1v = feature_vector_for_event(event, context, event.occurred_at)
    b0 = b0_risk_index(b0v)
    b1 = b1_risk_index(b1v)
    blend = round(0.45 * b0 + 0.55 * b1, 4)
    f = b1v.as_dict()
    reasons: list[DecisionReasonV2] = []
    if f["merchant_fanin"] >= 1 and f["rapid_forward_ratio"] < 0.2:
        action = DecisionAction.ALLOW; reasons.append(_v2_reason("R_MERCHANT_FANIN", "merchant_fanin")); blend = min(blend, 0.2)
    elif f["recurring_pair"] >= 1 and f["rapid_forward_ratio"] < 0.2:
        action = DecisionAction.ALLOW; reasons.append(_v2_reason("R_RECURRING_PAIR", "recurring_pair")); blend = min(blend, 0.2)
    elif f["refund_like"] >= 1 and f["rapid_forward_ratio"] < 0.2:
        action = DecisionAction.ALLOW; reasons.append(_v2_reason("R_REFUND_LIKE", "refund_like")); blend = min(blend, 0.2)
    elif f["household_like"] >= 1 and f["rapid_forward_ratio"] < 0.2:
        action = DecisionAction.ALLOW; reasons.append(_v2_reason("R_HOUSEHOLD", "household_like")); blend = min(blend, 0.2)
    elif f["rapid_forward_ratio"] >= 0.5 or f["structuring"] >= 1 or (f["fan_out"] >= 3 and f["payee_age_new"] >= 1) or blend >= 0.72:
        action = DecisionAction.ANALYST_REVIEW; reasons.append(_v2_reason("R_RAPID_FORWARD" if f["rapid_forward_ratio"] >= 0.5 else "R_B1_MOTIF", "rapid_forward_ratio" if f["rapid_forward_ratio"] >= 0.5 else "motif_score"))
    elif f["delayed_hop"] >= 1 or (f["urgent_context"] >= 1 and f["payee_age_new"] >= 1) or blend >= 0.55:
        action = DecisionAction.STEP_UP; reasons.append(_v2_reason("R_URGENT_NEW_PAYEE" if f["urgent_context"] and f["payee_age_new"] else "R_DELAYED_HOP", "urgent_context" if f["urgent_context"] and f["payee_age_new"] else "delayed_hop_gap_min"))
    elif f["new_payee_no_onward"] >= 1 or blend >= 0.32:
        action = DecisionAction.WARN_AND_VERIFY; reasons.append(_v2_reason("R_NEW_PAYEE", "new_payee_no_onward"))
    else:
        action = DecisionAction.ALLOW; reasons.append(_v2_reason("R_NO_STRONG_MOTIF", "motif_score"))
    if context.participation.participation in (Participation.LOCAL_ONLY, Participation.PARTIAL) and action == DecisionAction.ANALYST_REVIEW:
        action = DecisionAction.STEP_UP
        reasons.append(_v2_reason("R_PARTIAL_VIEW", "participation_ratio", "local_only" if context.participation.local_only else "partial"))
    reasons.extend([_v2_reason("R_B0_HEURISTIC", "b0_risk_index", b0), _v2_reason("R_B1_MOTIF", "b1_risk_index", b1)])
    evidence = [EvidenceItemV2(evidence_id="ev_" + event.event_id.replace("evt_", "")[:60], kind=EvidenceKind.MOTIF, summary_code=EvidenceSummaryCode.CURRENT_EVENT, institution_id=event.institution_id, observed_at=event.occurred_at, expires_at=now + timedelta(hours=6), coverage=context.evidence_coverage)]
    return RiskDecisionV2(
        event_id=event.event_id, trace_id=event.trace_id, as_of=now, subject_event_time=event.occurred_at,
        execution_mode=execution_mode, action=action, risk_band=_v2_band(action), score=blend,
        score_kind=ScoreKind.RISK_INDEX, calibrated=False, reasons=reasons, evidence=evidence,
        evidence_coverage=context.evidence_coverage, participation=context.participation.participation,
        local_only=context.participation.local_only, consent_outcome=context.consent.outcome,
        uncertainty=_uncertainty(context.evidence_coverage, context.participation.participation),
        engine_version=V2_ENGINE_VERSION, b0_feature_contract=B0_CONTRACT, b0_feature_hash=B0_FEATURE_HASH,
        b1_feature_contract=MOTIF_CONTRACT, b1_feature_hash=MOTIF_FEATURE_HASH,
        calibration_status=CalibrationStatus.NOT_FITTED, expires_at=now + timedelta(minutes=60 if action == DecisionAction.ANALYST_REVIEW else 15),
    )
