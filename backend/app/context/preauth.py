"""Server-owned EarlyTrace v2 context and consent provider.

No network, bank, NPCI, cloud, or partner connector is present here. Context
comes only from registered synthetic events/fixtures and verified consent.
The registered event ledger is append-only from the API's perspective and is
stored beside PAUD when a durable path is configured.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Protocol

from app.models.preauth import (
    ConsentOutcome, ConsentRecord, EventSource, ExecutionMode, Participation,
    PreAuthEventV2,
)
from app.security.preauth_attestation import KeyRegistry, event_digest, verify_consent

DISABLED_EXTERNAL_SOURCES = frozenset({"EXTERNAL_BANK", "BANK", "NPCI", "UPI_SWITCH", "CLOUD"})
ALLOWED_EVENT_SOURCES = frozenset(item.value for item in EventSource)


class SourceRejected(ValueError):
    pass


def require_event_source(source: EventSource | str) -> EventSource:
    value = source.value if isinstance(source, EventSource) else str(source)
    if value not in ALLOWED_EVENT_SOURCES:
        raise SourceRejected("event source is not enabled")
    return EventSource(value)


class ContextFailure(str, Enum):
    NONE = "NONE"
    MISSING_CONSENT = "MISSING_CONSENT"
    INVALID_CONSENT = "INVALID_CONSENT"
    EXPIRED_CONSENT = "EXPIRED_CONSENT"
    REVOKED_CONSENT = "REVOKED_CONSENT"
    CONTEXT_CONFLICT = "CONTEXT_CONFLICT"
    UNAVAILABLE = "CONTEXT_UNAVAILABLE"
    INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True)
class ConsentResult:
    outcome: ConsentOutcome
    verified: bool
    granting_institution: str | None = None
    receiving_institution: str | None = None


@dataclass(frozen=True)
class ParticipationResult:
    participation: Participation
    local_only: bool

    def __post_init__(self) -> None:
        if self.local_only != (self.participation == Participation.LOCAL_ONLY):
            raise ValueError("local_only must be derived from participation")


@dataclass(frozen=True)
class CurrentEventRecord:
    event: PreAuthEventV2
    attestation_verified: bool = True
    local_authorized: bool = False
    registered_at: datetime | None = None


@dataclass(frozen=True)
class ContextResult:
    current_event: CurrentEventRecord
    events: tuple[PreAuthEventV2, ...]
    consent: ConsentResult
    participation: ParticipationResult
    expected_institutions: frozenset[str]
    hub_available: bool
    evidence_coverage: float
    qualifying_prior_count: int
    local_sufficient: bool
    context_snapshot_id: str
    execution_mode: ExecutionMode = ExecutionMode.LIVE_SYNTHETIC
    failure_code: ContextFailure = ContextFailure.NONE
    visible_beacons: tuple[dict, ...] = ()
    visible_institutions: frozenset[str] | None = None


class CurrentEventStore(Protocol):
    def get(self, event_id: str, institution_id: str) -> CurrentEventRecord | None: ...


class ContextProvider(Protocol):
    def get(self, current_event, principal, server_now: datetime, mode): ...


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("clock values must be timezone-aware")
    return value.astimezone(timezone.utc)


def _outcome_failure(outcome: ConsentOutcome) -> ContextFailure:
    return {
        ConsentOutcome.MISSING: ContextFailure.MISSING_CONSENT,
        ConsentOutcome.INVALID: ContextFailure.INVALID_CONSENT,
        ConsentOutcome.EXPIRED: ContextFailure.EXPIRED_CONSENT,
        ConsentOutcome.REVOKED: ContextFailure.REVOKED_CONSENT,
        ConsentOutcome.CONFLICT: ContextFailure.CONTEXT_CONFLICT,
    }.get(outcome, ContextFailure.NONE)


class _ContextLedger:
    """Small trusted context ledger; requests never write to it."""

    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.conn.execute("PRAGMA busy_timeout=5000")
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS context_events (
            institution_id TEXT NOT NULL, event_id TEXT NOT NULL,
            event_json TEXT NOT NULL, attestation_verified INTEGER NOT NULL,
            registered_at TEXT NOT NULL,
            PRIMARY KEY (institution_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS context_local_authorizations (
            institution_id TEXT NOT NULL, event_id TEXT NOT NULL,
            event_digest TEXT NOT NULL, issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL, revoked_at TEXT,
            PRIMARY KEY (institution_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS context_consents (
            subject_event_id TEXT PRIMARY KEY, consent_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS context_fixtures (
            fixture_id TEXT PRIMARY KEY, institution_id TEXT NOT NULL,
            event_id TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS context_config (
            institution_id TEXT PRIMARY KEY, expected_json TEXT NOT NULL,
            hub_available INTEGER NOT NULL
        );
        """)

    def close(self) -> None:
        self.conn.close()


class VerifiedContextProvider:
    """Server-owned synthetic context registry with an exhaustive consent matrix."""

    def __init__(self, *, registry: KeyRegistry | None = None, clock=None, storage_path: str = ":memory:"):
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.registry = registry or KeyRegistry(clock=self.clock)
        self._ledger = _ContextLedger(storage_path)
        self._events: dict[tuple[str, str], CurrentEventRecord] = {}
        self._history: dict[str, list[PreAuthEventV2]] = {}
        self._consent: dict[str, ConsentRecord] = {}
        self._expected: dict[str, frozenset[str]] = {}
        self._hub: dict[str, bool] = {}
        self._fixtures: dict[str, tuple[str, str]] = {}
        self._local_auth: dict[tuple[str, str], tuple[str, datetime, datetime, datetime | None]] = {}
        self._snapshot = 0
        self._load_ledger()

    def _load_ledger(self) -> None:
        with self._ledger.lock:
            for row in self._ledger.conn.execute("SELECT * FROM context_events ORDER BY registered_at"):
                event = PreAuthEventV2.model_validate(json.loads(row["event_json"]))
                key = (row["institution_id"], row["event_id"])
                local = key in self._local_auth
                self._events[key] = CurrentEventRecord(
                    event=event,
                    attestation_verified=bool(row["attestation_verified"]),
                    local_authorized=local,
                    registered_at=_utc(datetime.fromisoformat(row["registered_at"])),
                )
                self._history.setdefault(event.institution_id, []).append(event)
            for row in self._ledger.conn.execute("SELECT * FROM context_local_authorizations"):
                key = (row["institution_id"], row["event_id"])
                self._local_auth[key] = (
                    row["event_digest"], _utc(datetime.fromisoformat(row["issued_at"])),
                    _utc(datetime.fromisoformat(row["expires_at"])),
                    _utc(datetime.fromisoformat(row["revoked_at"])) if row["revoked_at"] else None,
                )
                if key in self._events:
                    old = self._events[key]
                    self._events[key] = CurrentEventRecord(
                        old.event, old.attestation_verified, True, old.registered_at,
                    )
            for row in self._ledger.conn.execute("SELECT * FROM context_consents"):
                self._consent[row["subject_event_id"]] = ConsentRecord.model_validate(json.loads(row["consent_json"]))
            for row in self._ledger.conn.execute("SELECT * FROM context_fixtures"):
                self._fixtures[row["fixture_id"]] = (row["institution_id"], row["event_id"])
            for row in self._ledger.conn.execute("SELECT * FROM context_config"):
                self._expected[row["institution_id"]] = frozenset(json.loads(row["expected_json"]))
                self._hub[row["institution_id"]] = bool(row["hub_available"])
            self._snapshot = len(self._events) + len(self._consent)

    def register_event(
        self, event: PreAuthEventV2, *, attestation_verified: bool = True,
        local_authorized: bool = True, history: list[PreAuthEventV2] | None = None,
        expected_institutions: set[str] | None = None, hub_available: bool = True,
        fixture_id: str | None = None,
    ) -> None:
        """Atomically append a trusted event and optional server fixture.

        ``history`` is an internal bootstrap input only.  The HTTP submission
        model cannot carry it and the route never calls this method.
        """
        require_event_source(event.event_source)
        now = _utc(self.clock())
        key = (event.institution_id, event.event_id)
        history_values = list(history or [])
        candidates = history_values + [event]
        with self._ledger.lock:
            self._ledger.conn.execute("BEGIN IMMEDIATE")
            try:
                for item in candidates:
                    require_event_source(item.event_source)
                    item_key = (item.institution_id, item.event_id)
                    existing = self._events.get(item_key)
                    if existing is not None and existing.event.model_dump(mode="json") != item.model_dump(mode="json"):
                        raise ValueError("conflicting duplicate event body")
                    stored = self._ledger.conn.execute(
                        "SELECT event_json FROM context_events WHERE institution_id=? AND event_id=?",
                        item_key,
                    ).fetchone()
                    if stored is not None and json.loads(stored[0]) != item.model_dump(mode="json"):
                        raise ValueError("conflicting duplicate event body")
                    if stored is None:
                        self._ledger.conn.execute(
                            "INSERT INTO context_events VALUES(?,?,?,?,?)",
                            (item.institution_id, item.event_id, json.dumps(item.model_dump(mode="json"), sort_keys=True),
                             int(attestation_verified if item_key == key else True), now.isoformat()),
                        )
                    bucket = self._history.setdefault(item.institution_id, [])
                    if all(old.event_id != item.event_id for old in bucket):
                        bucket.append(item)
                    if existing is None:
                        self._events[item_key] = CurrentEventRecord(
                            item, attestation_verified if item_key == key else True,
                            local_authorized if item_key == key else False, now,
                        )
                current = self._events[key]
                self._events[key] = CurrentEventRecord(event, attestation_verified, local_authorized, current.registered_at or now)
                expected = frozenset(expected_institutions or {event.institution_id})
                self._expected[event.institution_id] = expected
                self._hub[event.institution_id] = hub_available
                self._ledger.conn.execute(
                    "INSERT OR REPLACE INTO context_config VALUES(?,?,?)",
                    (event.institution_id, json.dumps(sorted(expected)), int(hub_available)),
                )
                if local_authorized:
                    expires = now + timedelta(hours=6)
                    auth = (event_digest(event), now, expires, None)
                    self._local_auth[key] = auth
                    self._ledger.conn.execute(
                        "INSERT OR REPLACE INTO context_local_authorizations VALUES(?,?,?,?,?,?)",
                        (event.institution_id, event.event_id, auth[0], auth[1].isoformat(), auth[2].isoformat(), None),
                    )
                else:
                    self._local_auth.pop(key, None)
                    self._ledger.conn.execute(
                        "DELETE FROM context_local_authorizations WHERE institution_id=? AND event_id=?",
                        key,
                    )
                if fixture_id:
                    old_fixture = self._fixtures.get(fixture_id)
                    fixture_key = key
                    if old_fixture is not None and old_fixture != fixture_key:
                        raise ValueError("conflicting fixture binding")
                    self._fixtures[fixture_id] = fixture_key
                    self._ledger.conn.execute(
                        "INSERT OR REPLACE INTO context_fixtures VALUES(?,?,?)",
                        (fixture_id, event.institution_id, event.event_id),
                    )
                self._snapshot += 1
                self._ledger.conn.commit()
            except Exception:
                self._ledger.conn.rollback()
                raise

    def register_fixture(self, fixture_id: str, event: PreAuthEventV2, **kwargs) -> None:
        if event.event_source not in (EventSource.SANDBOX_FIXTURE, EventSource.STAGING_REGISTERED_FIXTURE):
            raise SourceRejected("fixture source is not enabled")
        self.register_event(event, fixture_id=fixture_id, **kwargs)

    def register_consent(self, record: ConsentRecord) -> None:
        event_record = self.lookup(record.subject_event_id, record.receiving_institution)
        if event_record is None:
            raise ValueError("consent subject event is not registered")
        if (
            record.scope.value != "CONSENTED_BEACON"
            or record.event_digest != event_digest(event_record.event)
            or record.receiving_institution != event_record.event.institution_id
            or record.granting_institution == record.receiving_institution
        ):
            raise ValueError("consent binding is invalid")
        with self._ledger.lock:
            self._ledger.conn.execute("BEGIN IMMEDIATE")
            try:
                self._consent[record.subject_event_id] = record
                self._ledger.conn.execute(
                    "INSERT OR REPLACE INTO context_consents VALUES(?,?)",
                    (record.subject_event_id, json.dumps(record.model_dump(mode="json"), sort_keys=True)),
                )
                self._snapshot += 1
                self._ledger.conn.commit()
            except Exception:
                self._ledger.conn.rollback()
                raise

    def set_hub(self, institution_id: str, available: bool) -> None:
        expected = self._expected.get(institution_id, frozenset({institution_id}))
        self._expected[institution_id] = expected
        self._hub[institution_id] = available
        with self._ledger.lock:
            self._ledger.conn.execute(
                "INSERT OR REPLACE INTO context_config VALUES(?,?,?)",
                (institution_id, json.dumps(sorted(expected)), int(available)),
            )
            self._ledger.conn.commit()
        self._snapshot += 1

    def lookup(self, event_id: str, institution_id: str) -> CurrentEventRecord | None:
        return self._events.get((institution_id, event_id))

    def fixture_event(self, fixture_id: str, institution_id: str) -> CurrentEventRecord | None:
        key = self._fixtures.get(fixture_id)
        return self._events.get(key) if key and key[0] == institution_id else None

    def _local_authorization_valid(self, current: CurrentEventRecord, server_now: datetime) -> bool:
        if not current.local_authorized or not current.attestation_verified:
            return False
        record = self._local_auth.get((current.event.institution_id, current.event.event_id))
        if record is None:
            return False
        digest, issued_at, expires_at, revoked_at = record
        return (
            digest == event_digest(current.event)
            and issued_at <= server_now < expires_at
            and (revoked_at is None or server_now < revoked_at)
        )

    def _consent_result(self, current: CurrentEventRecord, server_now: datetime) -> ConsentResult:
        event = current.event
        if not current.attestation_verified:
            return ConsentResult(ConsentOutcome.INVALID, False)
        record = self._consent.get(event.event_id)
        if event.consent_scope.value == "LOCAL_BEHAVIOUR":
            if not self._local_authorization_valid(current, server_now):
                return ConsentResult(ConsentOutcome.INVALID, False, event.institution_id, event.institution_id)
            if record is not None:
                return ConsentResult(ConsentOutcome.CONFLICT, False, record.granting_institution, record.receiving_institution)
            return ConsentResult(ConsentOutcome.VERIFIED_LOCAL, True, event.institution_id, event.institution_id)
        if event.consent_scope.value != "CONSENTED_BEACON":
            return ConsentResult(ConsentOutcome.MISSING, False)
        if record is None:
            return ConsentResult(ConsentOutcome.MISSING, False)
        if (
            record.scope.value != "CONSENTED_BEACON"
            or record.subject_event_id != event.event_id
            or record.receiving_institution != event.institution_id
            or record.granting_institution == record.receiving_institution
        ):
            return ConsentResult(ConsentOutcome.CONFLICT, False, record.granting_institution, record.receiving_institution)
        result = verify_consent(
            record, self.registry, now=server_now,
            subject_event_digest=event_digest(event), receiving_institution=event.institution_id,
        )
        if result.reason == "CONSENT_BINDING_MISMATCH":
            return ConsentResult(ConsentOutcome.CONFLICT, False, record.granting_institution, record.receiving_institution)
        if result.reason == "EXPIRED":
            return ConsentResult(ConsentOutcome.EXPIRED, False, record.granting_institution, record.receiving_institution)
        if result.reason == "REVOKED":
            return ConsentResult(ConsentOutcome.REVOKED, False, record.granting_institution, record.receiving_institution)
        if not result.ok:
            return ConsentResult(ConsentOutcome.INVALID, False, record.granting_institution, record.receiving_institution)
        return ConsentResult(ConsentOutcome.VERIFIED_CROSS_INSTITUTION, True, record.granting_institution, record.receiving_institution)

    def get(self, current_event: CurrentEventRecord | PreAuthEventV2, principal, server_now: datetime, mode) -> ContextResult:
        now = _utc(server_now)
        try:
            execution_mode = mode if isinstance(mode, ExecutionMode) else ExecutionMode(mode)
        except ValueError:
            raise ValueError("unsupported execution mode") from None
        supplied = current_event.event if isinstance(current_event, CurrentEventRecord) else current_event
        current = self.lookup(supplied.event_id, supplied.institution_id)
        if current is None:
            raise LookupError("current event is not registered")
        if current.event.model_dump(mode="json") != supplied.model_dump(mode="json"):
            raise ValueError("current event is not the registered server event")
        event = current.event
        expected_mode = {
            EventSource.SYNTHETIC_GENERATOR: ExecutionMode.LIVE_SYNTHETIC,
            EventSource.SANDBOX_FIXTURE: ExecutionMode.SANDBOX_REPLAY,
            EventSource.STAGING_REGISTERED_FIXTURE: ExecutionMode.STAGING_REPLAY,
        }[event.event_source]
        if execution_mode != expected_mode:
            raise ValueError("execution mode does not match event source")
        if principal is not None and getattr(principal, "institution", None) not in (None, event.institution_id):
            raise PermissionError("principal is not bound to event institution")
        consent = self._consent_result(current, now)
        expected = self._expected.get(event.institution_id, frozenset({event.institution_id}))
        hub = self._hub.get(event.institution_id, True)
        all_events = tuple(
            item for institution in expected
            for item in self._history.get(institution, ())
        )
        prior = tuple(
            e for e in all_events
            if e.event_id != event.event_id and _utc(e.occurred_at) < _utc(event.occurred_at)
        )
        local_prior = tuple(e for e in prior if e.institution_id == event.institution_id)
        failure = _outcome_failure(consent.outcome)
        if failure == ContextFailure.NONE and now - _utc(event.occurred_at) > timedelta(hours=6):
            failure = ContextFailure.INSUFFICIENT_EVIDENCE

        if consent.outcome == ConsentOutcome.VERIFIED_CROSS_INSTITUTION:
            if not hub:
                visible_prior: tuple[PreAuthEventV2, ...] = ()
                participation = ParticipationResult(Participation.NONE, False)
                coverage = 0.0
                failure = ContextFailure.UNAVAILABLE
            else:
                visible_prior = prior
                available = {e.institution_id for e in visible_prior} | {event.institution_id}
                participation = ParticipationResult(
                    Participation.FULL if expected <= available else Participation.PARTIAL,
                    False,
                )
                coverage = 1.0 if participation.participation == Participation.FULL else 0.75
        elif consent.outcome == ConsentOutcome.VERIFIED_LOCAL:
            visible_prior = local_prior
            if not hub:
                participation = ParticipationResult(Participation.LOCAL_ONLY, True)
            else:
                participation = ParticipationResult(
                    Participation.FULL if expected <= {event.institution_id} else Participation.PARTIAL,
                    False,
                )
            coverage = 1.0 if self._local_authorization_valid(current, now) else 0.0
        else:
            visible_prior = ()
            participation = ParticipationResult(Participation.NONE, False)
            coverage = 0.0

        qualifying = len({e.event_id for e in visible_prior if e.payee_token == event.payee_token})
        known_age = event.payee_age_bucket.value != "unknown"
        local_sufficient = (
            consent.outcome in (ConsentOutcome.VERIFIED_LOCAL, ConsentOutcome.VERIFIED_CROSS_INSTITUTION)
            and current.attestation_verified and failure == ContextFailure.NONE
            and coverage >= 0.75 and (known_age or qualifying >= 2)
        )
        if failure == ContextFailure.NONE and not local_sufficient:
            failure = ContextFailure.INSUFFICIENT_HISTORY
        visible = (
            frozenset({event.institution_id})
            if consent.outcome == ConsentOutcome.VERIFIED_LOCAL
            else frozenset(expected)
            if consent.outcome == ConsentOutcome.VERIFIED_CROSS_INSTITUTION and hub
            else frozenset()
        )
        return ContextResult(
            current_event=current, events=tuple(visible_prior), consent=consent,
            participation=participation, expected_institutions=expected,
            hub_available=hub, evidence_coverage=round(coverage, 4),
            qualifying_prior_count=qualifying, local_sufficient=local_sufficient,
            context_snapshot_id=f"ctx-{self._snapshot:08d}", execution_mode=execution_mode,
            failure_code=failure, visible_beacons=(), visible_institutions=visible,
        )

    def close(self) -> None:
        self._ledger.close()


class FixtureContextProvider(VerifiedContextProvider):
    pass
