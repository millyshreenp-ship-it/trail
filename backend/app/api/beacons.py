"""Beacon ingestion: institution -> hub. Every beacon is verified before it touches the graph."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException

from app.api.deps import state_dep
from app.models.beacon import SignedBeacon
from app.state import HubState

router = APIRouter(prefix="/beacons", tags=["beacons"])

STATUS = {
    "UNKNOWN_OR_REVOKED_INSTITUTION": 401, "INSTITUTION_MISMATCH": 403, "BAD_SIGNATURE": 401,
    "STALE_EPOCH": 422, "ISSUED_IN_FUTURE": 422, "EXPIRED": 410,
    "REPLAY": 409, "INFLUENCE_CAP_EXCEEDED": 429,
}


@router.post("", status_code=202)
def ingest(signed: SignedBeacon, x_institution_id: str = Header(...), st: HubState = Depends(state_dep)):
    result = st.verifier.verify(signed, x_institution_id)
    if not result.ok:
        st.audit.append(x_institution_id, "institution", "BEACON_REJECTED", signed.beacon.token,
                        reason_code=result.reason)
        raise HTTPException(STATUS.get(result.reason, 400), {"error": result.reason})
    st.beacons.append(signed.beacon)
    a = st.audit.append(x_institution_id, "institution", "BEACON_ACCEPTED", signed.beacon.token,
                        details={"edge_type": signed.beacon.edge_type.value, "nonce": signed.beacon.nonce})

    # Hand off to the detection engine (Khanak) for any case whose trail this beacon extends.
    from app.api.cases import try_detect
    for case in list(st.cases.values()):
        if signed.beacon.token in st.descendants(case.seed_token):
            try_detect(st, case)
    return {"accepted": True, "audit_id": a["audit_id"]}
