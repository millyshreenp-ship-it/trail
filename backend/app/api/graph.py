"""Graph + audit endpoints for the dashboard (Cytoscape.js element format)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import require, state_dep
from app.api.review import get_case
from app.security.rbac import Perm, Principal
from app.state import HubState

router = APIRouter(tags=["graph"])


@router.get("/graph/{case_id}")
def case_graph(case_id: str, view: str = "trail", institution: str | None = None,
               user: Principal = Depends(require(Perm.CASE_READ)), st: HubState = Depends(state_dep)):
    """view=trail: full cross-institution graph. view=siloed&institution=X: what one bank alone sees."""
    case = get_case(st, case_id)
    if not case.ring:
        raise HTTPException(409, "No ring record yet")
    if view == "siloed" and not institution:
        raise HTTPException(422, "institution is required for the siloed view")
    hops = case.ring.hops
    keep = {h.hop_index for h in hops if view != "siloed" or h.institution == institution}
    nodes = [{"data": {"id": f"h{h.hop_index}", "label": f"{h.institution} #{h.hop_index}",
                       "institution": h.institution, "risk_level": h.risk_level,
                       "receiver_class": h.receiver_class, "tainted_lo": h.tainted_amount_lo,
                       "minutes_since_seed": h.minutes_since_seed, "reasons": h.reasons}}
             for h in hops if h.hop_index in keep]
    edge_pairs = case.ring.edges or [(a.hop_index, b.hop_index) for a, b in zip(hops, hops[1:])]
    edges = [{"data": {"id": f"e{a}_{b}", "source": f"h{a}", "target": f"h{b}"}}
             for a, b in edge_pairs if a in keep and b in keep]
    return {"case_id": case_id, "view": view, "nodes": nodes, "edges": edges,
            "hidden_hops": len(hops) - len(nodes)}


@router.get("/audit")
def audit_log(subject: str | None = None, user: Principal = Depends(require(Perm.AUDIT_READ)),
              st: HubState = Depends(state_dep)):
    return st.audit.entries(subject)


@router.get("/audit/verify")
def audit_verify(user: Principal = Depends(require(Perm.AUDIT_READ)), st: HubState = Depends(state_dep)):
    ok, bad = st.audit.verify_chain()
    return {"chain_intact": ok, "first_bad_seq": bad, "entries": len(st.audit.entries())}
