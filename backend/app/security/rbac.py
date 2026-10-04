"""Role-based access control (roles from spec M10) with dev API keys.

Roles: L1 analyst, L2 approver, auditor, institution admin.
SENIOR_APPROVER is an added role for the A4 senior sign-off.
Sandbox keys exist only when TRAIL_ENV=sandbox; production loads hashed keys from TRAIL_USERS_JSON (SSO is the target).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from enum import Enum


class Role(str, Enum):
    L1_ANALYST = "l1_analyst"
    L2_APPROVER = "l2_approver"
    SENIOR_APPROVER = "senior_approver"
    AUDITOR = "auditor"
    INSTITUTION_ADMIN = "institution_admin"


class Perm(str, Enum):
    CASE_READ = "case:read"
    CASE_CREATE = "case:create"
    CASE_PROPOSE = "case:propose"
    CASE_APPROVE = "case:approve"
    CASE_REJECT = "case:reject"
    CASE_ESCALATE = "case:escalate"
    OUTCOME_WRITE = "outcome:write"
    AUDIT_READ = "audit:read"
    COMPLAINT_INTAKE = "complaint:intake"
    INSTITUTION_MANAGE = "institution:manage"


ROLE_PERMS: dict[Role, set[Perm]] = {
    Role.L1_ANALYST: {Perm.CASE_READ, Perm.CASE_CREATE, Perm.CASE_PROPOSE,
                      Perm.CASE_ESCALATE, Perm.COMPLAINT_INTAKE},
    Role.L2_APPROVER: {Perm.CASE_READ, Perm.CASE_PROPOSE, Perm.CASE_APPROVE,
                       Perm.CASE_REJECT, Perm.CASE_ESCALATE},
    Role.SENIOR_APPROVER: {Perm.CASE_READ, Perm.CASE_APPROVE, Perm.CASE_REJECT, Perm.CASE_ESCALATE},
    Role.AUDITOR: {Perm.CASE_READ, Perm.AUDIT_READ},  # read-only
    Role.INSTITUTION_ADMIN: {Perm.OUTCOME_WRITE, Perm.INSTITUTION_MANAGE, Perm.COMPLAINT_INTAKE},
}


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: Role
    institution: str | None = None

    def can(self, perm: Perm) -> bool:
        return perm in ROLE_PERMS[self.role]


def default_dev_users() -> dict[str, Principal]:
    """api_key -> Principal. Dev only; disable with TRAIL_DISABLE_DEV_KEYS=1."""
    return {
        "dev-l1-key": Principal("analyst_asha", Role.L1_ANALYST),
        "dev-l2a-key": Principal("approver_ravi", Role.L2_APPROVER),
        "dev-l2b-key": Principal("approver_meera", Role.L2_APPROVER),
        "dev-senior-key": Principal("senior_iyer", Role.SENIOR_APPROVER),
        "dev-auditor-key": Principal("auditor_kapoor", Role.AUDITOR),
        "dev-admin-a-key": Principal("admin_bank_a", Role.INSTITUTION_ADMIN, "BANK_A"),
    }


class UserDirectory:
    def __init__(self, users: dict[str, Principal] | None = None):
        if users is None:
            users = self._from_env()
        self._users = users

    @staticmethod
    def _from_env() -> dict[str, Principal]:
        """TRAIL_USERS_JSON: {"<sha256(api_key)>": {"user_id":..,"role":..,"institution":..}}.
        Sandbox keys are added only when TRAIL_ENV=sandbox and TRAIL_DISABLE_DEV_KEYS != 1."""
        users: dict[str, Principal] = {}
        for digest, u in json.loads(os.environ.get("TRAIL_USERS_JSON", "{}")).items():
            users[digest] = Principal(u["user_id"], Role(u["role"]), u.get("institution"))
        if os.environ.get("TRAIL_ENV", "sandbox").lower() != "production" and os.environ.get("TRAIL_DISABLE_DEV_KEYS") != "1":
            users.update({hashlib.sha256(k.encode()).hexdigest(): p for k, p in default_dev_users().items()})
        return users

    def authenticate(self, api_key: str | None) -> Principal | None:
        digest = hashlib.sha256((api_key or "").encode()).hexdigest()
        match = None
        for stored, principal in self._users.items():  # constant-time compare, no early exit
            if hmac.compare_digest(stored, digest):
                match = principal
        return match
