"""Process-wide hub state. Audit log is durable (TRAIL_AUDIT_PATH); case/beacon stores are in-memory."""
from __future__ import annotations

import os
import threading
from collections import defaultdict
from datetime import datetime, timezone

from app.config import get_settings
from app.models.beacon import Beacon, EdgeType
from app.models.case import Case
from app.security.audit import AuditLog
from app.security.rbac import UserDirectory
from app.security.ratelimit import SlidingWindowLimiter
from app.security.signing import BeaconVerifier, InstitutionRegistry
from app.security.tokens import TokenService


class VictimBankDirectory:
    """Stand-in for 'the victim bank confirms its own debit record' (flow #2).
    In a real deployment this is a call to the bank; here banks register synthetic debits."""

    def __init__(self):
        self._debits: dict[str, dict[str, str]] = defaultdict(dict)  # inst -> token -> amount_bucket

    def register_debit(self, institution: str, token: str, amount_bucket: str) -> None:
        self._debits[institution][token] = amount_bucket

    def confirms(self, institution: str, candidate_tokens: set[str], amount_bucket: str) -> bool:
        for t in candidate_tokens:
            if self._debits[institution].get(t) == amount_bucket:
                return True
        return False


class HubState:
    def __init__(self, master_secret: bytes | None = None, clock=None):
        cfg = get_settings()
        secret = master_secret or cfg.master_secret.encode()
        self.tokens = TokenService(secret)
        self.audit = AuditLog(cfg.audit_path)
        self.users = UserDirectory()
        self.registry = InstitutionRegistry()
        kw = {"clock": clock} if clock else {}
        self.verifier = BeaconVerifier(self.registry, **kw)
        self.victim_banks = VictimBankDirectory()
        # Anti-probing: outsiders cannot enumerate whether an account/token is flagged.
        self.probe_limiter = SlidingWindowLimiter(max_events=30, window_s=60, **kw)
        self.now = lambda: datetime.now(timezone.utc)  # injectable clock (tests/demo)
        self.cases: dict[str, Case] = {}
        self.seed_index: dict[str, str] = {}              # first-hop token -> case_id (dedup)
        self.beacons: list[Beacon] = []
        self._case_counter = 1023
        self._lock = threading.Lock()

    def next_case_id(self) -> str:
        with self._lock:
            self._case_counter += 1
            return f"TRAIL-{self._case_counter}"

    # ----- two-key rule ------------------------------------------------------
    def evidence_kinds(self, seed_token: str) -> set[str]:
        """Independent evidence kinds seen for a trail rooted at seed_token."""
        kinds: set[str] = set()
        reachable = self.descendants(seed_token)
        for b in self.beacons:
            if b.token in reachable:
                if b.edge_type == EdgeType.COMPLAINT_SEED:
                    kinds.add("complaint")
                elif b.edge_type == EdgeType.BEHAVIOURAL:
                    kinds.add("behaviour")
        if seed_token in self.seed_index:
            kinds.add("complaint")
        return kinds

    def can_share_onward(self, seed_token: str) -> bool:
        """A beacon is not shared onward to a third institution until complaint + behaviour exist."""
        return {"complaint", "behaviour"} <= self.evidence_kinds(seed_token)

    def descendants(self, seed_token: str) -> set[str]:
        children: dict[str, list[str]] = defaultdict(list)
        for b in self.beacons:
            if b.parent_token:
                children[b.parent_token].append(b.token)
        seen, stack = {seed_token}, [seed_token]
        while stack:
            for c in children[stack.pop()]:
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        return seen


_state: HubState | None = None


def get_state() -> HubState:
    global _state
    if _state is None:
        _state = HubState()
    return _state


def reset_state(state: HubState | None = None) -> HubState:
    global _state
    _state = state or HubState()
    return _state
