"""M10 / human review and governance.

AI detects -> AI ranks -> human reviews -> human approves -> time-limited action
-> appeal/outcome -> feedback.

Hard guarantees enforced here:
  * No endpoint freezes anything. An approved action becomes an ActionOrder that the
    *institution* executes (execution = PENDING_INSTITUTION_EXECUTION).
  * Holds (A2-A4) need two kinds of evidence (complaint + behaviour) -- the two-key rule.
  * Holds are blocked on receivers classified as likely-legitimate (use A5 instead).
  * Lien amount is capped to the traced taint bound; every order expires.
  * Separation of duties: proposer cannot approve; an approver counts once.
  * Every step writes a hash-chained audit entry with a reason code.
"""
from __future__ import annotations

import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import require, state_dep
from app.models.case import (ACTION_LABELS, APPROVAL_POLICY, MAX_DURATION_HOURS, REASON_CODES,
                             ActionCode, ActionOrder, ActionProposal, Approval, Case, CaseStatus,
                             Outcome, ReceiverClass, RingHop, RiskLevel)
from app.security.rbac import Perm, Principal, Role
from app.state import HubState

router = APIRouter(prefix="/cases", tags=["review"])

HOLDS = {ActionCode.A2, ActionCode.A3, ActionCode.A4}
HIGH = {RiskLevel.HIGH, RiskLevel.CRITICAL}


class ProposalIn(BaseModel):
    hop_index: int
    action: ActionCode
    reason_code: str
    rationale: str
    duration_hours: int | None = None
    amount_cap: float | None = None


class DecisionIn(BaseModel):
    decision: str  # approve | reject | escalate
    note: str | None = None


class OutcomeIn(BaseModel):
    held_amount: float | None = None
    appealed: bool = False
    final_label: str | None = None  # confirmed_mule | legitimate | unresolved


# ---------- helpers -------------------------------------------------------------

def get_case(st: HubState, case_id: str) -> Case:
    c = st.cases.get(case_id)
    if not c:
        raise HTTPException(404, "Case not found")
    return c


def expire_orders(st: HubState, case: Case) -> None:
    now = st.now()
    for o in case.orders:
        if o.status == "ACTIVE" and now >= o.expires_at:
            o.status = "EXPIRED"
            st.audit.append("system", "system", "ORDER_EXPIRED", o.order_id, reason_code=o.reason_code)


def _hop(case: Case, idx: int) -> RingHop:
    if not case.ring:
        raise HTTPException(409, "Case has no ring record yet")
    for h in case.ring.hops:
        if h.hop_index == idx:
            return h
    raise HTTPException(404, f"No hop {idx}")


def proposal_state(case: Case, p: ActionProposal) -> str:
    if any(o.proposal_id == p.proposal_id for o in case.orders):
        return "APPROVED"
    if any(a.decision == "reject" and a.note and a.note.startswith(f"[{p.proposal_id}]") for a in case.approvals):
        return "REJECTED"
    return "PENDING"


def _approvals_for(case: Case, p: ActionProposal) -> list[Approval]:
    return [a for a in case.approvals if a.decision == "approve" and (a.note or "").startswith(f"[{p.proposal_id}]")]


def default_proposals(st: HubState, case: Case) -> list[ActionProposal]:
    """Translate the detection engine's per-hop assessment into candidate actions.
    These are *recommendations by the system*, never approvals."""
    out: list[ActionProposal] = []
    for h in case.ring.hops:
        if h.receiver_class == ReceiverClass.LEGITIMATE:
            act, rc, cap, why = ActionCode.A5, "RC03_LIKELY_LEGIT", None, \
                "Likely legitimate receiver: verification outreach instead of a hold"
        elif h.receiver_class == ReceiverClass.RECRUITED:
            act, rc, cap, why = ActionCode.A5, "RC01_TRACED_PASSTHROUGH", None, \
                "Possibly unwitting recruited account: verification outreach first"
        elif h.risk_level in HIGH:
            act = ActionCode.A2
            rc = "RC02_RING_STRUCTURE" if h.receiver_class == ReceiverClass.RING_CONTROLLED else "RC01_TRACED_PASSTHROUGH"
            cap, why = h.tainted_amount_lo, "High-confidence receiver: time-boxed hold on lower-bound tainted amount"
        elif h.risk_level == RiskLevel.MEDIUM:
            act, rc, cap, why = ActionCode.A1, "RC01_TRACED_PASSTHROUGH", None, "Enhanced monitoring for 24h"
        else:
            continue
        out.append(ActionProposal(
            proposal_id="P-" + uuid.uuid4().hex[:8].upper(), hop_index=h.hop_index, action=act,
            reason_code=rc, rationale=why, duration_hours=MAX_DURATION_HOURS[act],
            amount_cap=cap, proposed_by="trail-engine", proposed_at=st.now()))
    return out


def _issue_order(st: HubState, case: Case, p: ActionProposal, approvers: list[str], audit_id: str) -> ActionOrder:
    hop = _hop(case, p.hop_index)
    now = st.now()
    order = ActionOrder(
        order_id="ORD-" + uuid.uuid4().hex[:8].upper(), proposal_id=p.proposal_id, action=p.action,
        hop_index=p.hop_index, institution=hop.institution, reason_code=p.reason_code,
        audit_id=audit_id, issued_at=now, expires_at=now + timedelta(hours=p.duration_hours),
        amount_cap=p.amount_cap, approved_by=approvers)
    case.orders.append(order)
    return order


# ---------- endpoints -----------------------------------------------------------

@router.post("/{case_id}/proposals", status_code=201)
def propose(case_id: str, body: ProposalIn, user: Principal = Depends(require(Perm.CASE_PROPOSE)),
            st: HubState = Depends(state_dep)):
    case = get_case(st, case_id)
    hop = _hop(case, body.hop_index)
    if body.reason_code not in REASON_CODES:
        raise HTTPException(422, f"Unknown reason code. Valid: {sorted(REASON_CODES)}")
    if len(body.rationale.strip()) < 10:
        raise HTTPException(422, "A written rationale is required")

    act = body.action
    if act in HOLDS:
        if hop.receiver_class == ReceiverClass.LEGITIMATE:
            raise HTTPException(422, "Receiver classified likely-legitimate: use A5 verification outreach, not a hold")
        kinds = {"complaint"} | ({"behaviour"} if hop.risk_level in HIGH or "behaviour" in st.evidence_kinds(case.seed_token) else set())
        if not {"complaint", "behaviour"} <= kinds:
            raise HTTPException(422, "Two-key rule: holds need both complaint and behavioural evidence")
        bound = hop.tainted_amount_hi if act in {ActionCode.A3} else hop.tainted_amount_lo
        if act != ActionCode.A4:
            if body.amount_cap is None or body.amount_cap > bound + 1e-9:
                raise HTTPException(422, f"amount_cap required and must not exceed the traced bound ({bound})")

    dur = body.duration_hours or MAX_DURATION_HOURS[act]
    if dur <= 0 or dur > MAX_DURATION_HOURS[act]:
        raise HTTPException(422, f"duration_hours must be 1..{MAX_DURATION_HOURS[act]} for {act.value}")

    p = ActionProposal(proposal_id="P-" + uuid.uuid4().hex[:8].upper(), hop_index=body.hop_index, action=act,
                       reason_code=body.reason_code, rationale=body.rationale, duration_hours=dur,
                       amount_cap=body.amount_cap, proposed_by=user.user_id, proposed_at=st.now())
    case.proposals.append(p)
    case.status = CaseStatus.UNDER_REVIEW
    a = st.audit.append(user.user_id, user.role.value, "ACTION_PROPOSED", case_id, reason_code=p.reason_code,
                        details={"proposal_id": p.proposal_id, "action": act.value, "hop": p.hop_index})
    return _after_proposal(st, case, p, a["audit_id"])


def _after_proposal(st: HubState, case: Case, p: ActionProposal, audit_id: str) -> dict:
    pol = APPROVAL_POLICY[p.action]
    if pol["auto"]:  # A0/A1 only: monitoring, never a hold or freeze
        a = st.audit.append("policy", "system", "AUTO_APPROVED_MONITORING", case.case_id,
                            reason_code=p.reason_code, details={"proposal_id": p.proposal_id})
        order = _issue_order(st, case, p, ["auto-policy"], a["audit_id"])
        case.status = CaseStatus.ACTION_APPROVED
        return {"proposal": p, "auto_approved": True, "order": order}
    return {"proposal": p, "auto_approved": False, "required": pol, "audit_id": audit_id}


@router.post("/{case_id}/proposals/{proposal_id}/decision")
def decide(case_id: str, proposal_id: str, body: DecisionIn, user: Principal = Depends(require(Perm.CASE_READ)),
           st: HubState = Depends(state_dep)):
    case = get_case(st, case_id)
    expire_orders(st, case)
    p = next((x for x in case.proposals if x.proposal_id == proposal_id), None)
    if not p:
        raise HTTPException(404, "Proposal not found")
    if proposal_state(case, p) != "PENDING":
        raise HTTPException(409, f"Proposal already {proposal_state(case, p)}")

    need = {"approve": Perm.CASE_APPROVE, "reject": Perm.CASE_REJECT, "escalate": Perm.CASE_ESCALATE}.get(body.decision)
    if need is None:
        raise HTTPException(422, "decision must be approve | reject | escalate")
    if not user.can(need):
        st.audit.append(user.user_id, user.role.value, "ACCESS_DENIED", case_id, reason_code="RBAC")
        raise HTTPException(403, f"Role '{user.role.value}' cannot {body.decision}")

    tagged = f"[{proposal_id}] {body.note or ''}".strip()

    if body.decision == "approve":
        if user.user_id == p.proposed_by:
            raise HTTPException(403, "Separation of duties: proposer cannot approve their own proposal")
        if any(a.approver == user.user_id for a in _approvals_for(case, p)):
            raise HTTPException(409, "You have already approved this proposal")
    a = st.audit.append(user.user_id, user.role.value, f"PROPOSAL_{body.decision.upper()}", case_id,
                        reason_code=p.reason_code, details={"proposal_id": proposal_id, "action": p.action.value})
    case.approvals.append(Approval(approver=user.user_id, role=user.role.value, decision=body.decision,
                                   note=tagged, ts=st.now(), audit_id=a["audit_id"]))

    if body.decision == "reject":
        case.status = CaseStatus.REJECTED if not any(proposal_state(case, x) == "PENDING" for x in case.proposals) else CaseStatus.UNDER_REVIEW
        return {"proposal_state": "REJECTED", "audit_id": a["audit_id"]}
    if body.decision == "escalate":
        case.status = CaseStatus.ESCALATED
        return {"proposal_state": "PENDING", "case_status": case.status, "audit_id": a["audit_id"]}

    # approve: check whether policy is satisfied
    pol = APPROVAL_POLICY[p.action]
    appr = _approvals_for(case, p)
    seniors = {x.approver for x in appr if x.role == Role.SENIOR_APPROVER.value}
    regular = {x.approver for x in appr if x.role != Role.SENIOR_APPROVER.value}
    if pol["senior"]:
        satisfied = len(regular) >= pol["n_approvers"] and len(seniors) >= 1
    else:
        satisfied = len(regular | seniors) >= pol["n_approvers"]
    if not satisfied:
        return {"proposal_state": "PENDING", "approvals_so_far": sorted(regular | seniors),
                "required": pol, "audit_id": a["audit_id"]}

    order = _issue_order(st, case, p, sorted(regular | seniors), a["audit_id"])
    case.status = CaseStatus.ACTION_APPROVED
    st.audit.append(user.user_id, user.role.value, "ORDER_ISSUED", order.order_id,
                    reason_code=order.reason_code, details={"expires_at": order.expires_at.isoformat()})
    return {"proposal_state": "APPROVED", "order": order, "audit_id": order.audit_id,
            "reason_code": order.reason_code, "expires_at": order.expires_at,
            "note": "Trail issues the order; the institution executes it. Nothing is frozen automatically."}


@router.post("/{case_id}/orders/{order_id}/release")
def release(case_id: str, order_id: str, user: Principal = Depends(require(Perm.CASE_APPROVE)),
            st: HubState = Depends(state_dep)):
    case = get_case(st, case_id)
    o = next((x for x in case.orders if x.order_id == order_id), None)
    if not o:
        raise HTTPException(404, "Order not found")
    o.status = "RELEASED"
    a = st.audit.append(user.user_id, user.role.value, "ORDER_RELEASED", order_id, reason_code=o.reason_code)
    return {"order_id": order_id, "status": o.status, "audit_id": a["audit_id"]}


@router.post("/{case_id}/orders/{order_id}/outcome")
def outcome(case_id: str, order_id: str, body: OutcomeIn, user: Principal = Depends(require(Perm.OUTCOME_WRITE)),
            st: HubState = Depends(state_dep)):
    """Outcome feedback from the institution: held amount, appeals, final label."""
    case = get_case(st, case_id)
    o = next((x for x in case.orders if x.order_id == order_id), None)
    if not o:
        raise HTTPException(404, "Order not found")
    if user.institution != o.institution:
        raise HTTPException(403, "Only the executing institution can report the outcome")
    case.outcomes.append(Outcome(order_id=order_id, held_amount=body.held_amount, appealed=body.appealed,
                                 final_label=body.final_label, reported_by=user.user_id, ts=st.now()))
    if body.appealed:
        case.status = CaseStatus.UNDER_REVIEW
        o.status = "RELEASED" if body.final_label == "legitimate" else o.status
    a = st.audit.append(user.user_id, user.role.value, "OUTCOME_REPORTED", order_id,
                        details={"appealed": body.appealed, "final_label": body.final_label})
    return {"recorded": True, "audit_id": a["audit_id"]}
