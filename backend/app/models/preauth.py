"""EarlyTrace pre-authorisation contracts.

Strict, privacy-minimised events for a synthetic payment-fraud prototype.
Raw account numbers, credentials, contact data, and message content are rejected.
Scoring actions are advisory: allow, warn, step-up, analyst review, or unknown.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "earlytrace.preauth.v1"
DECISION_SCHEMA = "earlytrace.decision.v1"
FEEDBACK_SCHEMA = "earlytrace.feedback.v1"

AMOUNT_BUCKETS = ("0_1k", "1k_10k", "10k_50k", "50k_100k", "100k_500k", "500k_plus")
RAILS = ("UPI", "IMPS", "NEFT", "RTGS", "WALLET")

# Names that must never appear on an event, decision, or audit detail payload.
FORBIDDEN_FIELDS = frozenset({
    "account_number", "account_no", "account", "iban", "pan", "aadhaar", "aadhar",
    "pin", "otp", "mpin", "password", "cvv",
    "phone", "phone_number", "mobile", "email", "message_body", "sms", "transcript",
    "audio_path", "audio", "device_fingerprint", "device_id", "ip", "ip_address",
    "contact_list", "contacts", "vpa", "upi_id", "customer_name", "name",
})


class DecisionAction(str, Enum):
    ALLOW = "ALLOW"
    WARN_AND_VERIFY = "WARN_AND_VERIFY"
    STEP_UP = "STEP_UP"
    ANALYST_REVIEW = "ANALYST_REVIEW"
    UNKNOWN = "UNKNOWN"


class SessionContext(str, Enum):
    ROUTINE = "ROUTINE"
    FAMILIAR_PAYEE = "FAMILIAR_PAYEE"
    NEW_BENEFICIARY = "NEW_BENEFICIARY"
    URGENT_SOCIAL_ENGINEERING = "URGENT_SOCIAL_ENGINEERING"
    MERCHANT_CHECKOUT = "MERCHANT_CHECKOUT"


class PayeeAgeBucket(str, Enum):
    NEW = "new"
    D0_7 = "0_7d"
    D7_30 = "7_30d"
    D30_90 = "30_90d"
    D90_PLUS = "90d_plus"
    UNKNOWN = "unknown"


class ConsentScope(str, Enum):
    LOCAL_BEHAVIOUR = "LOCAL_BEHAVIOUR"
    CONSENTED_BEACON = "CONSENTED_BEACON"
    NONE = "NONE"


class RiskBand(str, Enum):
    LOW = "LOW"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"


def _reject_forbidden(name: str) -> None:
    if name.lower() in FORBIDDEN_FIELDS:
        raise ValueError(f"forbidden field: {name}")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LocalSignalFlags(_Strict):
    new_beneficiary: bool = False
    urgent_context: bool = False
    rapid_forward_observed: bool = False
    partial_participation: bool = False
    evidence_stale: bool = False
    hub_unavailable: bool = False


class EvidenceItem(_Strict):
    evidence_id: str = Field(pattern=r"^ev_[a-z0-9_\-]{4,64}$")
    kind: Literal["local_behaviour", "beacon", "motif", "coverage"]
    observed_at: datetime
    expires_at: datetime | None = None
    institution_id: str | None = None
    coverage: float = Field(ge=0, le=1)
    fresh: bool = True


class DecisionReason(_Strict):
    code: str = Field(pattern=r"^[A-Z0-9_]{3,64}$")
    feature: str = Field(max_length=64)
    template: str = Field(max_length=240)
    value: float | str | None = None


class PreAuthEvent(_Strict):
    schema_version: Literal["earlytrace.preauth.v1", "earlytrace.preauth.v2"] = SCHEMA_VERSION
    event_id: str = Field(pattern=r"^evt_[a-z0-9_-]{6,64}$")
    occurred_at: datetime
    as_of: datetime
    institution_id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,32}$")
    event_source: str = "SYNTHETIC_GENERATOR"
    rail: str
    source_token: str = Field(pattern=r"^(tok_[0-9a-f]{32}|acct_[a-z0-9_]{1,64})$")
    payee_token: str = Field(pattern=r"^(tok_[0-9a-f]{32}|acct_[a-z0-9_]{1,64})$")
    amount_bucket: str
    payee_age_bucket: PayeeAgeBucket
    session_context: SessionContext
    consent_scope: ConsentScope
    trace_id: str = Field(pattern=r"^trace[a-z0-9_\-]{4,64}$")
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9_\-]{8,80}$")

    @field_validator("rail")
    @classmethod
    def _rail(cls, v: str) -> str:
        v = v.upper()
        if v not in RAILS:
            raise ValueError("unsupported rail")
        return v

    @field_validator("amount_bucket")
    @classmethod
    def _bucket(cls, v: str) -> str:
        if v not in AMOUNT_BUCKETS:
            raise ValueError("unknown amount bucket")
        return v

    @field_validator("occurred_at", "as_of")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return v.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _order(self) -> "PreAuthEvent":
        if self.occurred_at > self.as_of:
            raise ValueError("occurred_at is after as_of")
        if self.source_token == self.payee_token:
            raise ValueError("source and payee tokens must differ")
        if self.schema_version == "earlytrace.preauth.v2":
            if not re.fullmatch(r"tok_[0-9a-f]{32}", self.source_token) or not re.fullmatch(r"tok_[0-9a-f]{32}", self.payee_token):
                raise ValueError("v2 events require live tokens")
            if not re.fullmatch(r"^trace_[a-z0-9_-]{4,64}$", self.trace_id):
                raise ValueError("v2 trace id is invalid")
            if not re.fullmatch(r"^idem_[A-Za-z0-9_-]{8,64}$", self.idempotency_key):
                raise ValueError("v2 idempotency key is invalid")
            if self.event_source not in ("SYNTHETIC_GENERATOR", "SANDBOX_FIXTURE", "STAGING_REGISTERED_FIXTURE"):
                raise ValueError("event source is not enabled")
        return self


class RiskDecision(_Strict):
    schema_version: Literal["earlytrace.decision.v1"] = DECISION_SCHEMA
    event_id: str
    trace_id: str
    as_of: datetime
    action: DecisionAction
    risk_band: RiskBand
    score: float | None = Field(default=None, ge=0, le=1)
    calibrated: bool = False
    reasons: list[DecisionReason] = []
    evidence: list[EvidenceItem] = []
    coverage: float = Field(ge=0, le=1)
    participation: Literal["local_only", "partial", "full", "none"] = "none"
    unknown_reason: str | None = None
    engine_version: str
    audit_id: str | None = None
    expires_at: datetime | None = None
    irreversible: Literal[False] = False
    classical_score: float | None = Field(default=None, ge=0, le=1)
    classical_version: str | None = None

    @model_validator(mode="after")
    def _unknown_consistency(self) -> "RiskDecision":
        if self.action == DecisionAction.UNKNOWN and self.unknown_reason is None:
            raise ValueError("UNKNOWN decisions require unknown_reason")
        if self.calibrated and self.score is None:
            raise ValueError("calibrated decisions require a score")
        return self


class FeedbackLabel(str, Enum):
    CONFIRMED_MULE_MOVEMENT = "confirmed_mule_movement"
    LEGITIMATE = "legitimate"
    INCONCLUSIVE = "inconclusive"


class FeedbackEvent(_Strict):
    schema_version: Literal["earlytrace.feedback.v1"] = FEEDBACK_SCHEMA
    feedback_id: str = Field(pattern=r"^fb_[a-z0-9_\-]{4,64}$")
    event_id: str = Field(pattern=r"^evt_[a-z0-9_\-]{6,64}$")
    submitted_at: datetime
    analyst_id: str = Field(pattern=r"^[a-z0-9_]{3,64}$")
    label: FeedbackLabel
    quarantined: Literal[True] = True


class PreAuthRequest(_Strict):
    event: PreAuthEvent
    prior_events: list[PreAuthEvent] = Field(default_factory=list, max_length=200)
    hub_available: bool = True
    participating_institutions: list[str] = Field(default_factory=list, max_length=16)


def walk_forbidden(payload: object, path: str = "") -> list[str]:
    """Return dotted paths whose key is a forbidden raw identifier."""
    found: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            if str(key).lower() in FORBIDDEN_FIELDS:
                found.append(f"{path}.{key}" if path else str(key))
            found.extend(walk_forbidden(value, f"{path}.{key}" if path else str(key)))
    elif isinstance(payload, list):
        for i, value in enumerate(payload):
            found.extend(walk_forbidden(value, f"{path}[{i}]"))
    return found


# --- v2 strict contract extensions -----------------------------------------
# The v1 classes above remain importable for the frozen offline evaluator.
# These names are the server-owned v2 wire/domain contracts.

V2_SCHEMA_VERSION = "earlytrace.preauth.v2"
V2_DECISION_SCHEMA = "earlytrace.decision.v2"
V2_FEEDBACK_SCHEMA = "earlytrace.feedback.v2"


class EventSource(str, Enum):
    SYNTHETIC_GENERATOR = "SYNTHETIC_GENERATOR"
    SANDBOX_FIXTURE = "SANDBOX_FIXTURE"
    STAGING_REGISTERED_FIXTURE = "STAGING_REGISTERED_FIXTURE"


class ExecutionMode(str, Enum):
    LIVE_SYNTHETIC = "LIVE_SYNTHETIC"
    SANDBOX_REPLAY = "SANDBOX_REPLAY"
    STAGING_REPLAY = "STAGING_REPLAY"


class Participation(str, Enum):
    NONE = "NONE"
    LOCAL_ONLY = "LOCAL_ONLY"
    PARTIAL = "PARTIAL"
    FULL = "FULL"


class ConsentOutcome(str, Enum):
    MISSING = "MISSING"
    INVALID = "INVALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    CONFLICT = "CONFLICT"
    VERIFIED_LOCAL = "VERIFIED_LOCAL"
    VERIFIED_CROSS_INSTITUTION = "VERIFIED_CROSS_INSTITUTION"


class UnknownReason(str, Enum):
    MISSING_CONSENT = "MISSING_CONSENT"
    STALE_EVENT = "STALE_EVENT"
    INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    CONTEXT_UNAVAILABLE = "CONTEXT_UNAVAILABLE"
    FUTURE_EVENT_TIME = "FUTURE_EVENT_TIME"
    CALIBRATION_UNAVAILABLE = "CALIBRATION_UNAVAILABLE"
    CALIBRATION_MISMATCH = "CALIBRATION_MISMATCH"
    CONTEXT_CONFLICT = "CONTEXT_CONFLICT"


class ScoreKind(str, Enum):
    NONE = "NONE"
    RISK_INDEX = "RISK_INDEX"
    CALIBRATED_PROBABILITY = "CALIBRATED_PROBABILITY"


class CalibrationStatus(str, Enum):
    NOT_FITTED = "NOT_FITTED"
    REJECTED = "REJECTED"
    VERIFIED = "VERIFIED"
    UNAVAILABLE = "UNAVAILABLE"


class ReasonBucket(str, Enum):
    NEW = "new"
    KNOWN = "known"
    UNDER_15M = "under_15m"
    TWO_H_TO_18H = "2h_to_18h"
    MERCHANT = "merchant"
    RECURRING = "recurring"
    REFUND = "refund"
    HOUSEHOLD = "household"
    PARTIAL = "partial"
    LOCAL_ONLY = "local_only"
    FULL = "full"
    FRESH = "fresh"
    STALE = "stale"


class EvidenceKind(str, Enum):
    MOTIF = "motif"
    COVERAGE = "coverage"
    CONSENT = "consent"
    BEACON = "beacon"


class EvidenceSummaryCode(str, Enum):
    CURRENT_EVENT = "current_event"
    MOTIF_RAPID_FORWARD = "motif_rapid_forward"
    MOTIF_NEW_PAYEE = "motif_new_payee"
    MOTIF_DELAYED_HOP = "motif_delayed_hop"
    COVERAGE_LOCAL = "coverage_local"
    COVERAGE_PARTIAL = "coverage_partial"
    CONSENT_VERIFIED = "consent_verified"
    BEACON_VERIFIED = "beacon_verified"


V2_REASON_CODES = (
    "R_MERCHANT_FANIN", "R_RECURRING_PAIR", "R_REFUND_LIKE", "R_HOUSEHOLD",
    "R_RAPID_FORWARD", "R_STRUCTURING", "R_FAN_OUT", "R_FAN_IN",
    "R_DELAYED_HOP", "R_URGENT_NEW_PAYEE", "R_NEW_PAYEE",
    "R_PARTIAL_VIEW", "R_B0_HEURISTIC", "R_B1_MOTIF", "R_HUB_UNAVAILABLE",
    "R_NO_STRONG_MOTIF", "R_INSUFFICIENT", "R_DECLARATION_MISMATCH",
)
V2_REASON_FEATURES = (
    "merchant_fanin", "recurring_pair", "refund_like", "household_like",
    "rapid_forward_ratio", "structuring", "fan_out", "fan_in",
    "delayed_hop_gap_min", "urgent_context", "new_payee_no_onward",
    "participation_ratio", "b0_risk_index", "b1_risk_index", "hub_status",
    "motif_score", "coverage", "declaration",
)


class PreAuthEventV2(_Strict):
    schema_version: Literal["earlytrace.preauth.v2"] = V2_SCHEMA_VERSION
    event_id: str = Field(pattern=r"^evt_[a-z0-9_-]{6,64}$")
    occurred_at: datetime
    as_of: datetime
    institution_id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,32}$")
    event_source: EventSource
    rail: Literal["UPI", "IMPS", "NEFT", "RTGS", "WALLET"]
    source_token: str = Field(pattern=r"^tok_[0-9a-f]{32}$")
    payee_token: str = Field(pattern=r"^tok_[0-9a-f]{32}$")
    amount_bucket: Literal["0_1k", "1k_10k", "10k_50k", "50k_100k", "100k_500k", "500k_plus"]
    payee_age_bucket: PayeeAgeBucket
    session_context: SessionContext
    consent_scope: ConsentScope
    trace_id: str = Field(pattern=r"^trace_[a-z0-9_-]{4,64}$")
    idempotency_key: str = Field(pattern=r"^idem_[A-Za-z0-9_-]{8,64}$")

    @field_validator("occurred_at", "as_of")
    @classmethod
    def _v2_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _v2_order(self) -> "PreAuthEventV2":
        if self.occurred_at > self.as_of:
            raise ValueError("occurred_at is after as_of")
        if self.source_token == self.payee_token:
            raise ValueError("source and payee tokens must differ")
        return self


CanonicalPreAuthEvent = PreAuthEventV2
V2PreAuthEvent = PreAuthEventV2


class UnsupportedSchemaEnvelope(_Strict):
    schema_version: str = Field(pattern=r"^earlytrace\.preauth\.v[0-9]+$")
    event_id: str = Field(pattern=r"^evt_[a-z0-9_-]{6,64}$")
    occurred_at: datetime
    institution_id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,32}$")
    trace_id: str = Field(pattern=r"^trace_[a-z0-9_-]{4,64}$")
    idempotency_key: str = Field(pattern=r"^idem_[A-Za-z0-9_-]{8,64}$")

    @field_validator("occurred_at")
    @classmethod
    def _safe_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _not_v2(self) -> "UnsupportedSchemaEnvelope":
        if self.schema_version == V2_SCHEMA_VERSION:
            raise ValueError("supported schema is not an unsupported envelope")
        return self


class EventAttestation(_Strict):
    event_id: str = Field(pattern=r"^evt_[a-z0-9_-]{6,64}$")
    institution_id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,32}$")
    event_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    expires_at: datetime
    issuer_key_version: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,31}$")
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]+$")

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _attestation_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _attestation_window(self) -> "EventAttestation":
        if self.expires_at <= self.issued_at:
            raise ValueError("attestation expiry must be after issue time")
        return self


class ConsentRecord(_Strict):
    consent_id: str = Field(pattern=r"^con_[a-z0-9_-]{8,64}$")
    subject_event_id: str = Field(pattern=r"^evt_[a-z0-9_-]{6,64}$")
    granting_institution: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,32}$")
    receiving_institution: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,32}$")
    scope: ConsentScope
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    event_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    verifier_key_version: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,31}$")
    signed_payload: str | None = Field(default=None, max_length=8192)
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]+$")

    @field_validator("issued_at", "expires_at", "revoked_at")
    @classmethod
    def _consent_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(timezone.utc) if value is not None else None


class PreAuthSubmission(_Strict):
    schema_version: Literal["earlytrace.preauth.v2"] = V2_SCHEMA_VERSION
    event: PreAuthEventV2
    attestation: EventAttestation
    trace_id: str = Field(pattern=r"^trace_[a-z0-9_-]{4,64}$")
    idempotency_key: str = Field(pattern=r"^idem_[A-Za-z0-9_-]{8,64}$")
    declared_payee_age_bucket: PayeeAgeBucket | None = None
    declared_session_context: SessionContext | None = None
    declared_consent_scope: ConsentScope | None = None
    fixture_id: str | None = Field(default=None, pattern=r"^fx_[a-z0-9_-]{8,64}$")

    @model_validator(mode="after")
    def _binding(self) -> "PreAuthSubmission":
        if self.trace_id != self.event.trace_id or self.idempotency_key != self.event.idempotency_key:
            raise ValueError("submission metadata does not match event")
        if self.attestation.event_id != self.event.event_id or self.attestation.institution_id != self.event.institution_id:
            raise ValueError("attestation is not bound to event")
        return self


class UncertaintySummary(_Strict):
    level: Literal["LOW", "MEDIUM", "HIGH"]
    reasons: list[UnknownReason] = Field(default_factory=list, max_length=8)


class DecisionReasonV2(_Strict):
    code: Literal[tuple(V2_REASON_CODES)]
    feature: Literal[tuple(V2_REASON_FEATURES)]
    value: ReasonBucket | float | None = None
    template_id: str = Field(pattern=r"^[a-z0-9_]{3,64}$")

    @field_validator("value")
    @classmethod
    def _bounded_value(cls, value):
        if isinstance(value, float) and (value < 0 or value > 1 or round(value, 4) != value):
            raise ValueError("reason ratio must be between 0 and 1 at four decimals")
        return value


class EvidenceItemV2(_Strict):
    evidence_id: str = Field(pattern=r"^ev_[a-z0-9_-]{4,64}$")
    kind: EvidenceKind
    summary_code: EvidenceSummaryCode
    institution_id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,32}$")
    observed_at: datetime
    expires_at: datetime
    coverage: float = Field(ge=0, le=1, decimal_places=4)

    @field_validator("observed_at", "expires_at")
    @classmethod
    def _evidence_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)


class RiskDecisionV2(_Strict):
    schema_version: Literal["earlytrace.decision.v2"] = V2_DECISION_SCHEMA
    event_id: str = Field(pattern=r"^evt_[a-z0-9_-]{6,64}$")
    trace_id: str = Field(pattern=r"^trace_[a-z0-9_-]{4,64}$")
    as_of: datetime
    subject_event_time: datetime
    execution_mode: ExecutionMode
    action: DecisionAction
    risk_band: RiskBand
    score: float | None = Field(default=None, ge=0, le=1)
    score_kind: ScoreKind
    calibrated: bool
    reasons: list[DecisionReasonV2] = Field(default_factory=list, max_length=12)
    evidence: list[EvidenceItemV2] = Field(default_factory=list, max_length=16)
    evidence_coverage: float = Field(ge=0, le=1, decimal_places=4)
    participation: Participation
    local_only: bool
    consent_outcome: ConsentOutcome
    uncertainty: UncertaintySummary
    engine_version: str = Field(max_length=96)
    b0_feature_contract: str = Field(max_length=96)
    b0_feature_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    b1_feature_contract: str = Field(max_length=96)
    b1_feature_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    calibration_status: CalibrationStatus
    calibration_id: str | None = Field(default=None, pattern=r"^cal_[a-z0-9_-]{8,64}$")
    unknown_reason: UnknownReason | None = None
    expires_at: datetime
    audit_id: str | None = Field(default=None, pattern=r"^AUD-[A-Za-z0-9_-]{8,64}$")
    irreversible: Literal[False] = False

    @field_validator("as_of", "subject_event_time", "expires_at")
    @classmethod
    def _decision_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _consistency(self) -> "RiskDecisionV2":
        if self.expires_at <= self.as_of:
            raise ValueError("decision must expire after as_of")
        if self.local_only != (self.participation == Participation.LOCAL_ONLY):
            raise ValueError("local_only must be derived from participation")
        if self.action == DecisionAction.UNKNOWN:
            if self.risk_band != RiskBand.UNKNOWN or self.score is not None or self.score_kind != ScoreKind.NONE:
                raise ValueError("UNKNOWN decisions cannot carry a score")
            if self.calibrated or self.unknown_reason is None or self.calibration_id is not None:
                raise ValueError("UNKNOWN decision metadata is inconsistent")
            if self.uncertainty.level != "HIGH" or self.b0_feature_contract != "none" or self.b1_feature_contract != "none":
                raise ValueError("UNKNOWN decisions require high uncertainty and no feature contract")
        elif self.score_kind == ScoreKind.NONE or self.score is None:
            raise ValueError("scored decisions require a score kind and score")
        if self.score_kind == ScoreKind.CALIBRATED_PROBABILITY and not self.calibrated:
            raise ValueError("calibrated probability requires calibrated=true")
        if self.calibrated and self.calibration_id is None:
            raise ValueError("calibrated decisions require a calibration id")
        return self


class FeedbackEventV2(_Strict):
    schema_version: Literal["earlytrace.feedback.v2"] = V2_FEEDBACK_SCHEMA
    feedback_id: str = Field(pattern=r"^fb_[a-z0-9_-]{8,64}$")
    event_id: str = Field(pattern=r"^evt_[a-z0-9_-]{6,64}$")
    submitted_at: datetime
    label: FeedbackLabel
    quarantined: Literal[True] = True

    @field_validator("submitted_at")
    @classmethod
    def _feedback_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)


class ActionKind(str, Enum):
    VERIFY = "VERIFY"
    STEP_UP = "STEP_UP"
    REVIEW = "REVIEW"
    ESCALATE = "ESCALATE"


class ActionRequestV2(_Strict):
    schema_version: Literal["earlytrace.action.v2"] = "earlytrace.action.v2"
    action_id: str = Field(pattern=r"^act_[a-z0-9_-]{8,64}$")
    event_id: str = Field(pattern=r"^evt_[a-z0-9_-]{6,64}$")
    action: ActionKind
    note_code: Literal["VERIFICATION_REQUESTED", "STEP_UP_RECORDED", "REVIEW_RECORDED", "HUMAN_ESCALATION"]


class ActionReceiptV2(_Strict):
    schema_version: Literal["earlytrace.action.receipt.v2"] = "earlytrace.action.receipt.v2"
    event_id: str = Field(pattern=r"^evt_[a-z0-9_-]{6,64}$")
    action: ActionKind
    as_of: datetime
    expires_at: datetime
    duplicate: bool = False
    effect: Literal["recorded_only"] = "recorded_only"
    audit_id: str = Field(pattern=r"^AUD-[A-Za-z0-9_-]{8,64}$")


REASON_TEMPLATE_REGISTRY = {code.lower(): code for code in V2_REASON_CODES}

# Explicit v2 names are preferred by new callers; legacy names above remain
# available to the frozen evaluator and existing Trail fixtures.
StrictDecisionReason = DecisionReasonV2
StrictEvidenceItem = EvidenceItemV2
V2RiskDecision = RiskDecisionV2
V2FeedbackEvent = FeedbackEventV2
V2ActionRequest = ActionRequestV2
V2ActionReceipt = ActionReceiptV2
