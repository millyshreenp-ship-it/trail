"""Auth dependencies: RBAC via X-API-Key for humans; signatures for institutions."""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException

from app.security.rbac import Perm, Principal
from app.state import HubState, get_state


def state_dep() -> HubState:
    return get_state()


def current_user(x_api_key: str | None = Header(default=None),
                 st: HubState = Depends(state_dep)) -> Principal:
    p = st.users.authenticate(x_api_key)
    if p is None:
        raise HTTPException(401, "Missing or invalid API key")
    return p


def require(perm: Perm):
    def _dep(user: Principal = Depends(current_user), st: HubState = Depends(state_dep)) -> Principal:
        if not user.can(perm):
            st.audit.append(user.user_id, user.role.value, "ACCESS_DENIED", perm.value,
                            reason_code="RBAC", details={"needed": perm.value})
            raise HTTPException(403, f"Role '{user.role.value}' lacks permission '{perm.value}'")
        return user
    return _dep
