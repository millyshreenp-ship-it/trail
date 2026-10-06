"""Trusted EarlyTrace v2 decision API.

The public route is v2-only.  v1 remains available only through the offline
compatibility evaluator.  All writes are advisory, durable, and record-only.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.api.deps import require, state_dep
from app.context.preauth import ContextFailure
from app.detection.preauth import score_pre_auth_v2
from app.models.preauth import (
    CalibrationStatus, ConsentOutcome, DecisionAction, DecisionReasonV2,
    ExecutionMode, Participation, RiskBand, RiskDecisionV2, ScoreKind,
    UncertaintySummary, UnknownReason, UnsupportedSchemaEnvelope,
)
from app.models.preauth_v2 import PreAuthWireSubmission
from app.security.canonical_json import canonical_json_bytes
from app.security.input_boundary import InputBoundaryError, parse_bounded_json, validate_v2_payload
from app.security.preauth_attestation import PreAuthAttestor
from app.security.rbac import Perm, Principal
from app.state import HubState
from app.storage.preauth import DecisionInProgress, ReservationLost, StoreConflict

router = APIRouter(prefix="/preauth", tags=["preauth"])
_MAX_BODY = 65_536


class FeedbackBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["earlytrace.feedback.v2"]
    feedback_id: str = Field(pattern=r"^fb_[a-z0-9_-]{8,64}$")
    event_id: str = Field(pattern=r"^evt_[a-z0-9_-]{6,64}$")
    label: Literal["confirmed_mule_movement", "legitimate", "inconclusive"]


def _tenant(user: Principal) -> str:
    if not user.institution:
        raise HTTPException(403, "TENANT_REQUIRED")
    return user.institution


def _limit(user: Principal, st: HubState, subject: str) -> None:
    if not st.preauth_limiter.allow(f"{user.institution or 'unbound'}:{user.user_id}"):
        raise HTTPException(429, "Too many pre-auth requests", headers={"Retry-After": "60"})


def _body_hash(data: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(data)).hexdigest()


def _unsupported_unknown(envelope: UnsupportedSchemaEnvelope, now: datetime) -> dict:
    return RiskDecisionV2(
        event_id=envelope.event_id, trace_id=envelope.trace_id, as_of=now,
        subject_event_time=envelope.occurred_at, execution_mode=ExecutionMode.LIVE_SYNTHETIC,
        action=DecisionAction.UNKNOWN, risk_band=RiskBand.UNKNOWN, score=None,
        score_kind=ScoreKind.NONE, calibrated=False, reasons=[], evidence=[],
        evidence_coverage=0.0, participation=Participation.NONE, local_only=False,
        consent_outcome=ConsentOutcome.MISSING,
        uncertainty=UncertaintySummary(level="HIGH", reasons=[UnknownReason.UNSUPPORTED_SCHEMA]),
        engine_version="earlytrace-b0b1-heuristic-v2", b0_feature_contract="none", b0_feature_hash="0" * 64,
        b1_feature_contract="none", b1_feature_hash="0" * 64, calibration_status=CalibrationStatus.UNAVAILABLE,
        unknown_reason=UnknownReason.UNSUPPORTED_SCHEMA, expires_at=now + timedelta(minutes=15),
    ).model_dump(mode="json")


def _parse(request: Request, raw: bytes, now: datetime):
    try:
        parsed = parse_bounded_json(raw)
    except InputBoundaryError as exc:
        raise HTTPException(422, str(exc)) from None
    version = parsed.get("schema_version")
    if version == "earlytrace.preauth.v1":
        raise HTTPException(410, "v1 HTTP scoring is retired")
    if version != "earlytrace.preauth.v2":
        # Only the safe top-level envelope may produce a stored UNKNOWN.  The
        # old nested v1 request is rejected and is never passed to Pydantic/scoring.
        try:
            envelope = UnsupportedSchemaEnvelope.model_validate(parsed)
        except ValidationError:
            raise HTTPException(410, "unsupported preauth schema") from None
        return None, envelope
    try:
        safe = validate_v2_payload(parsed)
        submission = PreAuthWireSubmission.model_validate(safe)
    except (InputBoundaryError, ValidationError):
        raise HTTPException(422, "invalid preauth submission") from None
    if "as_of" in parsed or "prior_events" in parsed or "hub_available" in parsed or "participating_institutions" in parsed:
        raise HTTPException(422, "caller context is not accepted")
    if submission.event.event_id != submission.attestation.event_id or submission.event.institution_id != submission.attestation.institution_id:
        raise HTTPException(422, "attestation binding mismatch")
    return submission, None


def _unknown_from_context(event, ctx, now, reason: UnknownReason | None = None) -> RiskDecisionV2:
    from app.detection.preauth import _v2_unknown
    return _v2_unknown(event, now, ctx, reason or {"STALE_EVENT": UnknownReason.STALE_EVENT, "FUTURE_EVENT_TIME": UnknownReason.FUTURE_EVENT_TIME}.get(getattr(ctx.failure_code, "value", ctx.failure_code), UnknownReason.INSUFFICIENT_EVIDENCE))


def _declaration_reason(submission: PreAuthWireSubmission) -> bool:
    e = submission.event
    return any(value is not None and value != actual for value, actual in (
        (submission.declared_payee_age_bucket, e.payee_age_bucket),
        (submission.declared_session_context, e.session_context),
        (submission.declared_consent_scope, e.consent_scope),
    ))


@router.post("/decisions", status_code=200)
async def decide(request: Request, user: Principal = Depends(require(Perm.PREAUTH_SCORE)), st: HubState = Depends(state_dep)):
    tenant = _tenant(user)
    _limit(user, st, "score")
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) < 0:
                raise ValueError
        except ValueError:
            raise HTTPException(400, "invalid content length") from None
        if int(cl) > _MAX_BODY:
            raise HTTPException(413, "request body too large")
    raw = await request.body()
    if len(raw) > _MAX_BODY:
        raise HTTPException(413, "request body too large")
    now = st.now().astimezone(timezone.utc)
    submission, unsupported = _parse(request, raw, now)
    if unsupported is not None:
        if user.institution != unsupported.institution_id:
            raise HTTPException(403, "TENANT_REQUIRED")
        body_hash = _body_hash(unsupported.model_dump(mode="json"))
        try:
            reserved = st.preauth_store.reserve(tenant, unsupported.event_id, unsupported.idempotency_key, body_hash, now)
        except StoreConflict:
            raise HTTPException(409, "request conflict") from None
        if reserved.decision is not None:
            return reserved.decision
        decision = _unsupported_unknown(unsupported, now)
        try:
            return st.preauth_store.commit_decision(reserved.reservation, decision, {"reason_code": "UNSUPPORTED_SCHEMA"})
        except ReservationLost:
            raise HTTPException(503, "decision reservation lost") from None

    if submission.event.institution_id != tenant:
        raise HTTPException(403, "TENANT_REQUIRED")
    body_hash = _body_hash(submission.model_dump(mode="json"))
    try:
        reserved = st.preauth_store.reserve(tenant, submission.event.event_id, submission.idempotency_key, body_hash, now)
    except StoreConflict:
        raise HTTPException(409, "request conflict") from None
    except DecisionInProgress:
        raise HTTPException(409, "DECISION_IN_PROGRESS") from None
    if reserved.decision is not None:
        return reserved.decision

    from app.models.preauth import PreAuthEventV2
    event = PreAuthEventV2(
        schema_version=submission.event.schema_version, event_id=submission.event.event_id,
        occurred_at=submission.event.occurred_at, as_of=now, institution_id=submission.event.institution_id,
        event_source=submission.event.event_source, rail=submission.event.rail,
        source_token=submission.event.source_token, payee_token=submission.event.payee_token,
        amount_bucket=submission.event.amount_bucket, payee_age_bucket=submission.event.payee_age_bucket,
        session_context=submission.event.session_context, consent_scope=submission.event.consent_scope,
        trace_id=submission.event.trace_id, idempotency_key=submission.event.idempotency_key,
    )
    attestation = PreAuthAttestor(st.context.registry, clock=st.now)
    verified = attestation.verify_event(event, submission.attestation, now=now)
    if not verified.ok:
        st.preauth_store.fail(reserved.reservation, "ATTESTATION_INVALID")
        raise HTTPException(422, "invalid event attestation")
    fixture = st.context.fixture_event(submission.fixture_id, tenant) if submission.fixture_id else None
    if submission.fixture_id and fixture is None:
        st.preauth_store.fail(reserved.reservation, "FIXTURE_NOT_FOUND")
        raise HTTPException(422, "fixture not found")
    current = fixture or event
    if fixture is None:
        st.context.register_event(event, attestation_verified=True, local_authorized=True)
    if event.occurred_at > now + timedelta(seconds=60):
        st.preauth_store.fail(reserved.reservation, "FUTURE_EVENT_TIME")
        raise HTTPException(422, "FUTURE_EVENT_TIME")
    if event.occurred_at > now:
        ctx = st.context.get(current, user, now, ExecutionMode.LIVE_SYNTHETIC)
        from dataclasses import replace
        ctx = replace(ctx, failure_code=ContextFailure.INSUFFICIENT_EVIDENCE)
        decision = _unknown_from_context(event, ctx, now, UnknownReason.FUTURE_EVENT_TIME)
    else:
        ctx = st.context.get(current, user, now, ExecutionMode.LIVE_SYNTHETIC)
        if now - event.occurred_at > timedelta(hours=6):
            from dataclasses import replace
            ctx = replace(ctx, failure_code=ContextFailure.INSUFFICIENT_EVIDENCE)
            decision = _unknown_from_context(event, ctx, now, UnknownReason.STALE_EVENT)
        else:
            decision = score_pre_auth_v2(event, ctx, server_now=now)
    if _declaration_reason(submission) and decision.action != DecisionAction.UNKNOWN:
        reasons = list(decision.reasons) + [DecisionReasonV2(code="R_DECLARATION_MISMATCH", feature="declaration", value=None, template_id="r_declaration_mismatch")]
        decision = decision.model_copy(update={"reasons": reasons})
    try:
        return st.preauth_store.commit_decision(reserved.reservation, decision.model_dump(mode="json"), {"action": decision.action.value, "consent_outcome": decision.consent_outcome.value})
    except ReservationLost:
        raise HTTPException(503, "decision reservation lost") from None


def _load(event_id: str, user: Principal, st: HubState) -> dict:
    tenant = _tenant(user)
    _limit(user, st, "read")
    decision = st.preauth_store.get_decision(tenant, event_id)
    if decision is None:
        raise HTTPException(404, "not found")
    return decision


@router.get("/decisions/{event_id}")
def get_decision(event_id: str, user: Principal = Depends(require(Perm.PREAUTH_READ)), st: HubState = Depends(state_dep)):
    return _load(event_id, user, st)


@router.get("/decisions/{event_id}/view")
def view_decision(event_id: str, user: Principal = Depends(require(Perm.PREAUTH_READ)), st: HubState = Depends(state_dep)):
    return {"decision": _load(event_id, user, st), "excluded_future_events": True}


def _action(event_id: str, request: Request, kind: str, user: Principal, st: HubState):
    decision = _load(event_id, user, st)
    try:
        raw = parse_bounded_json(request._body if hasattr(request, "_body") and request._body else b"{}")
    except InputBoundaryError:
        raw = {}
    if not raw:
        raise HTTPException(422, "action receipt is required")
    allowed = {"schema_version", "action_id", "event_id", "action", "note_code"}
    if set(raw) - allowed or raw.get("event_id") != event_id or raw.get("action") != kind:
        raise HTTPException(422, "invalid action receipt")
    if raw.get("schema_version") != "earlytrace.action.v2" or raw.get("note_code") not in {"VERIFICATION_REQUESTED", "STEP_UP_RECORDED", "REVIEW_RECORDED", "HUMAN_ESCALATION", "DISPLAY_RECORDED"}:
        raise HTTPException(422, "invalid action schema")
    action_id = raw.get("action_id")
    if not isinstance(action_id, str) or not __import__("re").fullmatch(r"act_[a-z0-9_-]{8,64}", action_id):
        raise HTTPException(422, "invalid action id")
    eligible = {"DISPLAY": {"UNKNOWN", "ALLOW", "WARN_AND_VERIFY", "STEP_UP", "ANALYST_REVIEW"}, "REVIEW": {"UNKNOWN", "WARN_AND_VERIFY", "STEP_UP", "ANALYST_REVIEW"}, "STEP_UP": {"WARN_AND_VERIFY", "STEP_UP"}, "ESCALATE": {"UNKNOWN", "WARN_AND_VERIFY", "STEP_UP", "ANALYST_REVIEW"}}[kind]
    if decision["action"] not in eligible:
        raise HTTPException(409, "ACTION_NOT_ELIGIBLE")
    if datetime.fromisoformat(decision["expires_at"]) <= st.now():
        raise HTTPException(409, "ACTION_EXPIRED")
    body_hash = _body_hash(raw)
    receipt = {"schema_version": "earlytrace.action.receipt.v2", "event_id": event_id, "action": kind, "as_of": st.now().isoformat(), "expires_at": decision["expires_at"], "duplicate": False, "effect": "recorded_only", "audit_id": "PAUD-pending"}
    # The store audit ID is authoritative; replace the temporary field after its
    # transaction allocates a receipt audit row.
    try:
        result = st.preauth_store.put_action(user.institution, event_id, action_id, body_hash, receipt)
    except StoreConflict:
        raise HTTPException(409, "action conflict") from None
    return result


@router.post("/decisions/{event_id}/display")
async def display(event_id: str, request: Request, user: Principal = Depends(require(Perm.PREAUTH_READ)), st: HubState = Depends(state_dep)):
    await request.body()
    return _action(event_id, request, "DISPLAY", user, st)


@router.post("/decisions/{event_id}/review")
async def review(event_id: str, request: Request, user: Principal = Depends(require(Perm.PREAUTH_REVIEW)), st: HubState = Depends(state_dep)):
    await request.body()
    return _action(event_id, request, "REVIEW", user, st)


@router.post("/decisions/{event_id}/step-up")
async def step_up(event_id: str, request: Request, user: Principal = Depends(require(Perm.PREAUTH_REVIEW)), st: HubState = Depends(state_dep)):
    await request.body()
    return _action(event_id, request, "STEP_UP", user, st)


@router.post("/decisions/{event_id}/escalate")
async def escalate(event_id: str, request: Request, user: Principal = Depends(require(Perm.PREAUTH_REVIEW)), st: HubState = Depends(state_dep)):
    await request.body()
    return _action(event_id, request, "ESCALATE", user, st)


@router.post("/feedback", status_code=202)
async def feedback(request: Request, user: Principal = Depends(require(Perm.PREAUTH_REVIEW)), st: HubState = Depends(state_dep)):
    tenant = _tenant(user)
    _limit(user, st, "feedback")
    try:
        body = FeedbackBody.model_validate(parse_bounded_json(await request.body()))
    except (InputBoundaryError, ValidationError):
        raise HTTPException(422, "invalid feedback") from None
    decision = st.preauth_store.get_decision(tenant, body.event_id)
    if decision is None:
        raise HTTPException(404, "not found")
    raw = body.model_dump(mode="json")
    receipt = {"schema_version": "earlytrace.feedback.receipt.v2", "event_id": body.event_id, "feedback_id": body.feedback_id, "quarantined": True, "applied_to_model": False, "as_of": st.now().isoformat()}
    try:
        result = st.preauth_store.put_feedback(tenant, body.event_id, body.feedback_id, _body_hash(raw), receipt)
    except StoreConflict:
        raise HTTPException(409, "feedback conflict") from None
    return result
