"""Institution enrolment, token gateway and victim-bank debit confirmation (sandbox directory)."""
from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import require, state_dep
from app.security.rbac import Perm, Principal
from app.security.tokens import epoch_for
from app.state import HubState

router = APIRouter(prefix="/institutions", tags=["institutions"])


class EnrolIn(BaseModel):
    institution_id: str
    public_key_b64: str  # raw Ed25519 public key


class TokenReq(BaseModel):
    rail: str
    reference: str       # RRN / UTR; used once to derive the token, never stored
    date: str            # YYYY-MM-DD


class DebitIn(BaseModel):
    token: str
    amount_bucket: str


def _own_institution(user: Principal, institution_id: str) -> None:
    if user.institution != institution_id:
        raise HTTPException(403, "Institution admins can only act for their own institution")


@router.post("/enrol")
def enrol(body: EnrolIn, user: Principal = Depends(require(Perm.INSTITUTION_MANAGE)),
          st: HubState = Depends(state_dep)):
    _own_institution(user, body.institution_id)
    st.registry.register(body.institution_id, base64.b64decode(body.public_key_b64))
    a = st.audit.append(user.user_id, user.role.value, "INSTITUTION_ENROLLED", body.institution_id)
    return {"institution_id": body.institution_id, "audit_id": a["audit_id"]}


@router.post("/{institution_id}/revoke")
def revoke(institution_id: str, user: Principal = Depends(require(Perm.INSTITUTION_MANAGE)),
           st: HubState = Depends(state_dep)):
    _own_institution(user, institution_id)
    st.registry.revoke(institution_id)
    a = st.audit.append(user.user_id, user.role.value, "INSTITUTION_REVOKED", institution_id)
    return {"revoked": institution_id, "audit_id": a["audit_id"]}


@router.post("/token")
def issue_token(body: TokenReq, user: Principal = Depends(require(Perm.INSTITUTION_MANAGE)),
                st: HubState = Depends(state_dep)):
    """Token gateway. Rate-limited because an unrestricted tokeniser is a brute-force oracle."""
    if not st.probe_limiter.allow(f"token:{user.user_id}"):
        raise HTTPException(429, "Rate limit exceeded")
    from datetime import date
    tok = st.tokens.reference_token(body.rail, body.reference, epoch_for(date.fromisoformat(body.date)))
    return {"token": tok, "epoch": body.date}


@router.post("/{institution_id}/debits")
def register_debit(institution_id: str, body: DebitIn,
                   user: Principal = Depends(require(Perm.INSTITUTION_MANAGE)),
                   st: HubState = Depends(state_dep)):
    """DEMO STUB for flow #2: the bank records its own debit so complaints can be corroborated."""
    _own_institution(user, institution_id)
    st.victim_banks.register_debit(institution_id, body.token, body.amount_bucket)
    return {"ok": True}
