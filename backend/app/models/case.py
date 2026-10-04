"""Case models: RingRecord (contract with Khanak's detection engine), actions, approvals.

SAFETY RULE: AI detects -> AI ranks -> human reviews -> human approves ->
time-limited action -> appeal/outcome -> feedback.
Nothing in this module (or the API) freezes an account automatically.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReceiverClass(str, Enum):
    RING_CONTROLLED = "ring_controlled"
    RECRUITED = "recruited_account"
    LEGITIMATE = "legitimate_receiver"
    UNKNOWN = "unknown"


class ActionCode(str, Enum):
    A0 = "A0"  # Monitor
    A1 = "A1"  # Enhanced monitoring, 24h
    A2 = "A2"  # Hold on lower-bound tainted amount, time-boxed
    A3 = "A3"  # Extend toward upper bound
    A4 = "A4"  # Full account freeze (rare)
    A5 = "A5"  # Verification outreach (likely unwitting receivers)


ACTION_LABELS = {
    ActionCode.A0: "Monitor",
    ActionCode.A1: "Enhanced monitoring (24h)",
    ActionCode.A2: "Time-boxed hold on lower-bound tainted amount",
    ActionCode.A3: "Extend hold toward upper bound",
    ActionCode.A4: "Full account freeze (rare)",
    ActionCode.A5: "Verification outreach",
}

# Default approvals — to be validated with compliance (spec M8).
# n_approvers: distinct approvers needed. senior: one must hold SENIOR_APPROVER.
# auto: allowed without a human (monitoring only, never a hold/freeze).
APPROVAL_POLICY: dict[ActionCode, dict] = {
    ActionCode.A0: {"n_approvers": 0, "senior": False, "auto": True},
    ActionCode.A1: {"n_approvers": 0, "senior": False, "auto": True},
    ActionCode.A2: {"n_approvers": 1, "senior": False, "auto": False},
    ActionCode.A3: {"n_approvers": 2, "senior": False, "auto": False},
    ActionCode.A4: {"n_approvers": 2, "senior": True, "auto": False},
    ActionCode.A5: {"n_approvers": 1, "senior": False, "auto": False},
}

# Maximum lifetime per action (hours). Every hold/outreach auto-expires.
MAX_DURATION_HOURS = {
    ActionCode.A0: 24, ActionCode.A1: 24, ActionCode.A2: 24,
    ActionCode.A3: 24, ActionCode.A4: 12, ActionCode.A5: 72,
}

REASON_CODES = {
    "RC01_TRACED_PASSTHROUGH": "Traced pass-through of complaint funds",
    "RC02_RING_STRUCTURE": "Coordinated ring structure across institutions",
    "RC03_LIKELY_LEGIT": "Likely legitimate receiver; verification instead of hold",
    "RC04_LOW_CONFIDENCE": "Insufficient evidence for action",
    "RC05_DUPLICATE": "Duplicate of an existing case",
    "RC06_INSUFFICIENT_CORROBORATION": "Corroboration requirement not met",
    "RC07_POLICY_OVERRIDE": "Reviewer judgement",
}


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    UNDER_REVIEW = "UNDER_REVIEW"
    ACTION_APPROVED = "ACTION_APPROVED"
    REJECTED = "REJECTED"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"


# ----- Contract with Khanak's detection engine ---------------------------------

class RingHop(BaseModel):
    hop_index: int
    institution: str
    receiver_pseudonym: str            # case-scoped pseudonym, never a raw account id
    token: str
    tainted_amount_lo: float = 0.0     # synthetic rupees; lower taint bound
    tainted_amount_hi: float = 0.0
    minutes_since_seed: float = 0.0
    risk_score: float = Field(ge=0, le=1)
    risk_level: RiskLevel
    receiver_class: ReceiverClass = ReceiverClass.UNKNOWN
    p_hold_now: float | None = Field(default=None, ge=0, le=1)  # optional (M6)
    reasons: list[str] = []


class RingRecord(BaseModel):
    """What Khanak's graph/ring-detection hands to the case layer."""
    pattern: str                       # chain | fanout | fanin | cross_bank_hop
    seed_token: str
    n_hops: int
    institutions: list[str]
    hops: list[RingHop]
    edges: list[tuple[int, int]] = []  # (from_hop, to_hop); empty => linear chain by hop_index
    total_tainted_lo: float
    confidence: float = Field(ge=0, le=1)
    reasons: list[str]
    recommended_action: ActionCode


# ----- Case workflow ------------------------------------------------------------

class ActionProposal(BaseModel):
    proposal_id: str
    hop_index: int
    action: ActionCode
    reason_code: str
    rationale: str
    duration_hours: int
    amount_cap: float | None = None    # lien capped to traced amount
    proposed_by: str
    proposed_at: datetime


class Approval(BaseModel):
    approver: str
    role: str
    decision: str                      # approve | reject | escalate
    note: str | None = None
    ts: datetime
    audit_id: str


class ActionOrder(BaseModel):
    """Issued only after the required human approvals. Time-limited by construction."""
    order_id: str
    proposal_id: str
    action: ActionCode
    hop_index: int
    institution: str
    reason_code: str
    audit_id: str
    issued_at: datetime
    expires_at: datetime
    amount_cap: float | None = None
    approved_by: list[str]
    status: str = "ACTIVE"             # ACTIVE | EXPIRED | RELEASED
    execution: str = "PENDING_INSTITUTION_EXECUTION"  # the institution executes, not Trail


class Outcome(BaseModel):
    order_id: str
    held_amount: float | None = None
    appealed: bool = False
    final_label: str | None = None     # confirmed_mule | legitimate | unresolved
    reported_by: str
    ts: datetime


class Case(BaseModel):
    case_id: str
    status: CaseStatus = CaseStatus.OPEN
    seed_token: str
    victim_institution: str
    rail: str
    created_at: datetime
    golden_window_expires_at: datetime
    ring: RingRecord | None = None
    proposals: list[ActionProposal] = []
    approvals: list[Approval] = []
    orders: list[ActionOrder] = []
    outcomes: list[Outcome] = []
    duplicate_complaints: int = 0
