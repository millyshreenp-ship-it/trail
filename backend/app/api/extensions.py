from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import require, state_dep
from app.security.extensions import ExtensionRejected
from app.security.rbac import Perm, Principal
from app.state import HubState

router = APIRouter(prefix="/api/workspace", tags=["optional verification"])


class DeviceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(pattern=r"^device_[a-z0-9_-]{8,64}$")
    public_key_b64: str = Field(min_length=40, max_length=48)


class ChallengeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(pattern=r"^device_[a-z0-9_-]{8,64}$")


class AcknowledgementBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signature_b64: str = Field(min_length=80, max_length=100)


def _invoke(user, state, method, *args):
    if not user.institution:
        raise HTTPException(403, "TENANT_REQUIRED")
    if not state.preauth_limiter.allow(f"extension:{user.institution}:{user.user_id}"):
        raise HTTPException(429, "Too many verification requests", headers={"Retry-After": "60"})
    try:
        return method(user.institution, *args)
    except ExtensionRejected as error:
        raise HTTPException(409, str(error)) from None


@router.post("/devices")
def enroll(body: DeviceBody, user: Principal = Depends(require(Perm.INSTITUTION_MANAGE)), st: HubState = Depends(state_dep)):
    return _invoke(user, st, st.extensions.enroll, body.device_id, body.public_key_b64)


@router.post("/devices/{device_id}/revoke")
def revoke(device_id: str, user: Principal = Depends(require(Perm.INSTITUTION_MANAGE)), st: HubState = Depends(state_dep)):
    return _invoke(user, st, st.extensions.revoke, device_id)


@router.post("/decisions/{event_id}/device-challenge")
def challenge(event_id: str, body: ChallengeBody, user: Principal = Depends(require(Perm.PREAUTH_REVIEW)), st: HubState = Depends(state_dep)):
    current = st.context.lookup(event_id, user.institution or "")
    if current is None:
        raise HTTPException(404, "not found")
    details = {"amount_bucket": current.event.amount_bucket, "payee_pseudonym": st.tokens.to_case_display_pseudonym(event_id, current.event.payee_token)}
    return _invoke(user, st, st.extensions.challenge, event_id, body.device_id, details)


@router.post("/device-challenges/{challenge_id}/acknowledge")
def acknowledge(challenge_id: str, body: AcknowledgementBody, user: Principal = Depends(require(Perm.PREAUTH_REVIEW)), st: HubState = Depends(state_dep)):
    return _invoke(user, st, st.extensions.acknowledge, challenge_id, body.signature_b64)


@router.post("/checkpoints")
def checkpoint(user: Principal = Depends(require(Perm.PREAUTH_REVIEW)), st: HubState = Depends(state_dep)):
    return _invoke(user, st, st.extensions.checkpoint)


@router.get("/checkpoints/{checkpoint_id}/verify")
def verify(checkpoint_id: str, user: Principal = Depends(require(Perm.PREAUTH_READ)), st: HubState = Depends(state_dep)):
    return _invoke(user, st, st.extensions.verify_checkpoint, checkpoint_id)