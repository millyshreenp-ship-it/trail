"""Tenant-scoped analyst workspace; no payment execution surface."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import require, state_dep
from app.assistance import summarize
from app.models.preauth import EventSource, ExecutionMode
from app.security.rbac import Perm, Principal
from app.state import HubState

router = APIRouter(prefix="/api/workspace", tags=["workspace"])


def _tenant(user: Principal) -> str:
    if not user.institution:
        raise HTTPException(403, "TENANT_REQUIRED")
    return user.institution


@router.get("/session")
def session(user: Principal = Depends(require(Perm.PREAUTH_READ))):
    return {"user_id": user.user_id, "role": user.role.value, "institution": _tenant(user), "permissions": [permission.value for permission in Perm if user.can(permission)]}


@router.get("/decisions")
def decisions(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), user: Principal = Depends(require(Perm.PREAUTH_READ)), st: HubState = Depends(state_dep)):
    rows = st.preauth_store.list_decisions(_tenant(user), limit=limit, offset=offset)
    return {"items": rows, "offset": offset, "next_offset": offset + limit if len(rows) == limit else None}


@router.get("/decisions/{event_id}/evidence")
def evidence(event_id: str, user: Principal = Depends(require(Perm.PREAUTH_READ)), st: HubState = Depends(state_dep)):
    tenant = _tenant(user)
    decision = st.preauth_store.get_decision(tenant, event_id)
    current = st.context.lookup(event_id, tenant)
    if decision is None or current is None:
        raise HTTPException(404, "not found")
    mode = {EventSource.SYNTHETIC_GENERATOR: ExecutionMode.LIVE_SYNTHETIC, EventSource.SANDBOX_FIXTURE: ExecutionMode.SANDBOX_REPLAY, EventSource.STAGING_REGISTERED_FIXTURE: ExecutionMode.STAGING_REPLAY}[current.event.event_source]
    context = st.context.get(current, user, st.now(), mode)
    subject = current.event
    visible = [event for event in context.events if event.source_token in {subject.source_token, subject.payee_token} or event.payee_token in {subject.source_token, subject.payee_token}]
    graph_events = [*visible[-100:], subject]
    nodes = {}
    edges = []
    for event in graph_events:
        for token in (event.source_token, event.payee_token):
            pseudonym = st.tokens.to_case_display_pseudonym(event_id, token)
            nodes[pseudonym] = {"id": pseudonym, "label": "Subject payee" if token == subject.payee_token else "Counterparty", "institution": event.institution_id, "subject": token == subject.payee_token}
        edges.append({"id": event.event_id, "source": st.tokens.to_case_display_pseudonym(event_id, event.source_token), "target": st.tokens.to_case_display_pseudonym(event_id, event.payee_token), "amount_bucket": event.amount_bucket, "occurred_at": event.occurred_at.isoformat(), "pending": event.event_id == event_id})
    audit = [row for row in st.preauth_store.audit_entries(event_id) if row["tenant"] == tenant]
    return {"decision": decision, "nodes": list(nodes.values()), "edges": edges, "audit": audit, "excluded_future_events": True, "history_count": len(visible), "event_source": subject.event_source.value}


@router.get("/decisions/{event_id}/summary")
def summary(event_id: str, user: Principal = Depends(require(Perm.PREAUTH_READ)), st: HubState = Depends(state_dep)):
    tenant = _tenant(user)
    decision = st.preauth_store.get_decision(tenant, event_id)
    if decision is None:
        raise HTTPException(404, "not found")
    if not st.preauth_limiter.allow(f"assistant:{tenant}:{user.user_id}"):
        raise HTTPException(429, "Too many summary requests", headers={"Retry-After": "60"})
    return summarize(decision)