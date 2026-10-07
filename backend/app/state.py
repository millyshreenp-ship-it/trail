"""Process-wide hub state. Audit log is durable (TRAIL_AUDIT_PATH); case/beacon stores are in-memory."""
from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.config import PROFILE_SANDBOX, PROFILE_STAGING, get_settings
from app.context.preauth import VerifiedContextProvider
from app.models.beacon import Beacon, EdgeType
from app.models.case import Case
from app.models.preauth import EventSource, PreAuthEventV2
from app.security.audit import AuditLog
from app.security.preauth_attestation import PreAuthAttestor, event_digest
from app.security.rbac import UserDirectory
from app.security.ratelimit import SlidingWindowLimiter
from app.security.signing import BeaconVerifier, InstitutionRegistry
from app.security.tokens import TokenService
from app.security.extensions import EvidenceExtensions
from app.storage.preauth import SQLiteDecisionStore


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
        self.now = clock or (lambda: datetime.now(timezone.utc))
        self.context = VerifiedContextProvider(clock=self.now, storage_path=cfg.preauth_path)
        self.preauth_store = SQLiteDecisionStore(cfg.preauth_path, clock=self.now)
        self.extensions = EvidenceExtensions(self.preauth_store, secret, self.tokens, self.now)
        self._earlytrace_submission = self._bootstrap_earlytrace(cfg)
        kw = {"clock": clock} if clock else {}
        self.verifier = BeaconVerifier(self.registry, **kw)
        self.victim_banks = VictimBankDirectory()
        # Anti-probing: outsiders cannot enumerate whether an account/token is flagged.
        limiter_clock = (lambda: self.now().timestamp()) if clock else time.time
        self.probe_limiter = SlidingWindowLimiter(max_events=30, window_s=60, clock=limiter_clock)
        self.cases: dict[str, Case] = {}
        self.seed_index: dict[str, str] = {}              # first-hop token -> case_id (dedup)
        self.beacons: list[Beacon] = []
        self.preauth_limiter = SlidingWindowLimiter(max_events=60, window_s=60, clock=limiter_clock)
        self._case_counter = 1023
        self._lock = threading.Lock()

    def _bootstrap_earlytrace(self, cfg):
        """Register one deterministic local fixture and its attestation key.

        This is synthetic-only bootstrap for the sandbox console. Staging has
        no built-in users or demo key and therefore does not receive it.
        """
        if cfg.profile not in {PROFILE_SANDBOX, PROFILE_STAGING}:
            return None
        now = self.now().astimezone(timezone.utc)
        private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"trail-earlytrace-sandbox-key-v2").digest())
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        fixture_prefix = "sandbox" if cfg.profile == PROFILE_SANDBOX else "staging"
        fixture_source = EventSource.SANDBOX_FIXTURE if cfg.profile == PROFILE_SANDBOX else EventSource.STAGING_REGISTERED_FIXTURE
        key_version = f"{fixture_prefix}-v2"
        self.context.registry.register("BANK_A", key_version, public, active_at=now, expires_at=now + timedelta(days=365))
        fixture_id = f"fx_{fixture_prefix}_urgent01"
        current = self.context.fixture_event(fixture_id, "BANK_A")
        if current is None:
            event = PreAuthEventV2(
                event_id=f"evt_{fixture_prefix}_urgent1", occurred_at=now, as_of=now,
                institution_id="BANK_A", event_source=fixture_source,
                rail="UPI", source_token="tok_" + "1" * 32,
                payee_token="tok_" + "2" * 32, amount_bucket="1k_10k",
                payee_age_bucket="new", session_context="URGENT_SOCIAL_ENGINEERING",
                consent_scope="LOCAL_BEHAVIOUR", trace_id=f"trace_{fixture_prefix}01",
                idempotency_key=f"idem_{fixture_prefix}01",
            )
            self.context.register_fixture(fixture_id, event, expected_institutions={"BANK_A"}, hub_available=True)
        else:
            event = current.event
        signed = PreAuthAttestor(self.context.registry, clock=self.now).sign_event(
            event, private, key_version=key_version, issued_at=now,
            expires_at=now + timedelta(hours=6),
        )
        return {
            "schema_version": "earlytrace.preauth.v2",
            "event": {
                "schema_version": "earlytrace.preauth.v2", "event_id": event.event_id,
                "institution_id": event.institution_id, "event_digest": event_digest(event),
                "trace_id": event.trace_id, "idempotency_key": event.idempotency_key,
            },
            "attestation": signed.model_dump(mode="json"),
            "trace_id": event.trace_id, "idempotency_key": event.idempotency_key,
            "fixture_id": fixture_id,
            "declared_payee_age_bucket": event.payee_age_bucket.value,
            "declared_session_context": event.session_context.value,
            "declared_consent_scope": event.consent_scope.value,
        }

    def purge_expired_preauth(self, now: datetime | None = None) -> int:
        """Run the declared retention policy on the authoritative PAUD store."""
        return self.preauth_store.purge(now or self.now())["decisions"]

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
