"""Case APIs: queue, case card, and the hand-off from Khanak's detection engine."""
from __future__ import annotations

import importlib

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import require, state_dep
from app.api.review import default_proposals, expire_orders, get_case, proposal_state
from app.models.case import (ACTION_LABELS, ActionCode, Case, CaseStatus, ReceiverClass,
                             RiskLevel, RingRecord)
from app.security.rbac import Perm, Principal
from app.state import HubState

router = APIRouter(prefix="/cases", tags=["cases"])

LEVEL_ORDER = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


def case_card(case: Case) -> dict:
    """Compact card for the investigator dashboard (see spec section 9 example)."""
    card = {"case_id": case.case_id, "status": case.status, "victim_institution": case.victim_institution,
            "golden_window_expires_at": case.golden_window_expires_at,
            "duplicate_complaints": case.duplicate_complaints}
    if case.ring:
        r = case.ring
        top = max((h.risk_level for h in r.hops), key=lambda l: LEVEL_ORDER[l])
        card.update({
            "risk_level": top, "pattern": r.pattern,
            "potentially_traceable": r.total_tainted_lo, "n_institutions": len(r.institutions),
            "n_hops": r.n_hops, "confidence": r.confidence,
            "high_risk_receivers": sum(1 for h in r.hops if h.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
                                       and h.receiver_class != ReceiverClass.LEGITIMATE),
            "likely_legitimate": sum(1 for h in r.hops if h.receiver_class == ReceiverClass.LEGITIMATE),
            "recommended_action": r.recommended_action,
            "recommended_action_label": ACTION_LABELS[r.recommended_action],
            "reasons": r.reasons})
    return card


def try_detect(st: HubState, case: Case) -> bool:
    """Calls Khanak's engine if present: app.detection.graph.build_ring_record(beacons, seed_token) -> RingRecord | None.
    Absent engine => no-op; a ring can also be attached via POST /cases/{id}/ring."""
    try:
        mod = importlib.import_module("app.detection.graph")
        build = getattr(mod, "build_ring_record")
    except (ImportError, AttributeError):
        return False
    ring = build(
        [b for b in st.beacons if b.token in st.descendants(case.seed_token)],
        case.seed_token,
        case_id=case.case_id,
        token_service=st.tokens,
    )
    if ring is None:
        return False
    attach_ring(st, case, RingRecord.model_validate(ring), actor=("detection-engine", "system"))
    return True


def attach_ring(st: HubState, case: Case, ring: RingRecord, actor: tuple[str, str]) -> None:
    case.ring = ring
    # Refresh engine recommendations when a ring is (re)attached so amount caps and
    # reason codes track the latest detection output (manual POST or try_detect).
    fresh = [p for p in default_proposals(st, case) if p.action not in (ActionCode.A0, ActionCode.A1)]
    fresh_keys = {(p.hop_index, p.action) for p in fresh}
    kept = []
    for p in case.proposals:
        if proposal_state(case, p) != "PENDING":
            kept.append(p)  # never drop decided proposals
            continue
        if (p.hop_index, p.action) in fresh_keys and p.proposed_by == "trail-engine":
            continue  # replace stale engine proposal with the refreshed one
        kept.append(p)
    existing = {(p.hop_index, p.action) for p in kept if proposal_state(case, p) == "PENDING"}
    for p in fresh:
        if (p.hop_index, p.action) not in existing:
            kept.append(p)
    case.proposals = kept
    case.status = CaseStatus.UNDER_REVIEW if case.proposals else CaseStatus.OPEN
    st.audit.append(actor[0], actor[1], "RING_ATTACHED", case.case_id,
                    details={"pattern": ring.pattern, "hops": ring.n_hops,
                             "confidence": ring.confidence, "institutions": ring.institutions})


@router.get("")
def queue(user: Principal = Depends(require(Perm.CASE_READ)), st: HubState = Depends(state_dep)):
    """Ranked case queue: highest risk first, then least golden-window time remaining."""
    for c in st.cases.values():
        expire_orders(st, c)
    cards = [case_card(c) for c in st.cases.values()]
    cards.sort(key=lambda x: (-LEVEL_ORDER.get(x.get("risk_level", RiskLevel.LOW), 0),
                              x["golden_window_expires_at"]))
    return cards


@router.get("/{case_id}")
def detail(case_id: str, user: Principal = Depends(require(Perm.CASE_READ)), st: HubState = Depends(state_dep)):
    case = get_case(st, case_id)
    expire_orders(st, case)
    return {"card": case_card(case), "case": case,
            "proposal_states": {p.proposal_id: proposal_state(case, p) for p in case.proposals},
            "onward_sharing_allowed": st.can_share_onward(case.seed_token)}


@router.post("/{case_id}/ring")
def post_ring(case_id: str, ring: RingRecord, user: Principal = Depends(require(Perm.CASE_CREATE)),
              st: HubState = Depends(state_dep)):
    """Integration point: hand a ring record from the detection engine to the case layer."""
    case = get_case(st, case_id)
    attach_ring(st, case, ring, actor=(user.user_id, user.role.value))
    return case_card(case)
