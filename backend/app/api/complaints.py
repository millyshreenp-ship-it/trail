"""M1: Complaint intake and seeding.

Authenticated only; corroborated against the victim bank's own debit record
(otherwise rejected); deduplicated on first-hop token; starts the golden-window clock.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import require, state_dep
from app.models.beacon import amount_to_bucket
from app.models.case import Case
from app.security.rbac import Perm, Principal
from app.security.tokens import epoch_for
from app.state import HubState

router = APIRouter(prefix="/complaints", tags=["complaints"])

GOLDEN_WINDOW_MINUTES = 60  # assumption; see docs/assumptions.md


class ComplaintIn(BaseModel):
    victim_institution: str
    rail: str
    reference: str          # RRN/UTR from the victim; tokenised immediately, never stored
    amount: float           # synthetic rupees; bucketed immediately
    timestamp: datetime


@router.post("", status_code=201)
def file_complaint(body: ComplaintIn, user: Principal = Depends(require(Perm.COMPLAINT_INTAKE)),
                   st: HubState = Depends(state_dep)):
    epoch = epoch_for(body.timestamp)
    token = st.tokens.reference_token(body.rail, body.reference, epoch)
    bucket = amount_to_bucket(body.amount)
    # `body.reference` and the exact amount are not stored beyond this function.

    if not st.victim_banks.confirms(body.victim_institution,
                                    st.tokens.candidate_tokens(body.rail, body.reference, epoch), bucket):
        a = st.audit.append(user.user_id, user.role.value, "COMPLAINT_REJECTED", token,
                            reason_code="RC06_INSUFFICIENT_CORROBORATION",
                            details={"victim_institution": body.victim_institution})
        raise HTTPException(422, {"error": "Complaint not corroborated by victim bank debit record",
                                  "reason_code": "RC06_INSUFFICIENT_CORROBORATION",
                                  "audit_id": a["audit_id"]})

    existing = st.seed_index.get(token)
    if existing:
        case = st.cases[existing]
        case.duplicate_complaints += 1
        a = st.audit.append(user.user_id, user.role.value, "COMPLAINT_DEDUPLICATED", case.case_id,
                            reason_code="RC05_DUPLICATE")
        return {"case_id": case.case_id, "duplicate": True, "audit_id": a["audit_id"],
                "golden_window_expires_at": case.golden_window_expires_at}

    now = st.now()
    case = Case(case_id=st.next_case_id(), seed_token=token,
                victim_institution=body.victim_institution, rail=body.rail.upper(),
                created_at=now, golden_window_expires_at=now + timedelta(minutes=GOLDEN_WINDOW_MINUTES))
    st.cases[case.case_id] = case
    st.seed_index[token] = case.case_id
    a = st.audit.append(user.user_id, user.role.value, "CASE_SEEDED", case.case_id,
                        details={"seed_token": token, "amount_bucket": bucket})
    return {"case_id": case.case_id, "duplicate": False, "corroborated": True,
            "seed_token": token, "amount_bucket": bucket,
            "golden_window_expires_at": case.golden_window_expires_at, "audit_id": a["audit_id"]}
