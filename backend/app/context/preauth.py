"""Server-owned EarlyTrace v2 context and consent provider.

No network, bank, NPCI, cloud, or partner connector is present here.  Context
comes only from registered synthetic events/fixtures and verified consent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Protocol

from app.models.preauth import (
    ConsentOutcome, ConsentRecord, EventSource, Participation, PreAuthEventV2,
)
from app.security.preauth_attestation import KeyRegistry, event_digest, verify_consent, verify_event_attestation

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
    failure_code: ContextFailure = ContextFailure.NONE
    visible_beacons: tuple[dict, ...] = ()


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


class VerifiedContextProvider:
    """In-process synthetic context registry with an exhaustive consent matrix."""

    def __init__(self, *, registry: KeyRegistry | None = None, clock=None):
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.registry = registry or KeyRegistry(clock=self.clock)
        self._events: dict[tuple[str, str], CurrentEventRecord] = {}
        self._history: dict[str, list[PreAuthEventV2]] = {}
        self._consent: dict[str, ConsentRecord] = {}
        self._expected: dict[str, frozenset[str]] = {}
        self._hub: dict[str, bool] = {}
        self._fixtures: dict[str, tuple[str, str]] = {}
        self._snapshot = 0

    def register_event(self, event: PreAuthEventV2, *, attestation_verified: bool = True, local_authorized: bool = True, history: list[PreAuthEventV2] | None = None, expected_institutions: set[str] | None = None, hub_available: bool = True, fixture_id: str | None = None) -> None:
        require_event_source(event.event_source)
        key = (event.institution_id, event.event_id)
        for prior in history or self._history.get(key[0], []):
            if prior.event_id == event.event_id and prior.model_dump(mode="json") != event.model_dump(mode="json"):
                raise ValueError("conflicting duplicate event body")
        self._events[key] = CurrentEventRecord(event, attestation_verified, local_authorized, _utc(self.clock()))
        self._history[key[0]] = list(history or self._history.get(key[0], []))
        self._expected[event.institution_id] = frozenset(expected_institutions or {event.institution_id})
        self._hub[event.institution_id] = hub_available
        self._snapshot += 1
        if fixture_id:
            self._fixtures[fixture_id] = key

    def register_fixture(self, fixture_id: str, event: PreAuthEventV2, **kwargs) -> None:
        if event.event_source not in (EventSource.SANDBOX_FIXTURE, EventSource.STAGING_REGISTERED_FIXTURE):
            raise SourceRejected("fixture source is not enabled")
        self.register_event(event, fixture_id=fixture_id, **kwargs)

    def register_consent(self, record: ConsentRecord) -> None:
        self._consent[record.subject_event_id] = record
        self._snapshot += 1

    def set_hub(self, institution_id: str, available: bool) -> None:
        self._hub[institution_id] = available
        self._snapshot += 1

    def lookup(self, event_id: str, institution_id: str) -> CurrentEventRecord | None:
        return self._events.get((institution_id, event_id))

    def fixture_event(self, fixture_id: str, institution_id: str) -> CurrentEventRecord | None:
        key = self._fixtures.get(fixture_id)
        return self._events.get(key) if key and key[0] == institution_id else None

    def _consent_result(self, current: CurrentEventRecord, server_now: datetime) -> ConsentResult:
        event = current.event
        declared = event.consent_scope
        if not current.attestation_verified or not current.local_authorized:
            return ConsentResult(ConsentOutcome.INVALID, False)
        record = self._consent.get(event.event_id)
        if record is not None:
            if declared.value != "CONSENTED_BEACON":
                return ConsentResult(ConsentOutcome.CONFLICT, False, record.granting_institution, record.receiving_institution)
            if record.granting_institution == record.receiving_institution or record.receiving_institution != event.institution_id:
                return ConsentResult(ConsentOutcome.CONFLICT, False, record.granting_institution, record.receiving_institution)
            result = verify_consent(record, self.registry, now=server_now, subject_event_digest=event_digest(event), receiving_institution=event.institution_id)
            # The provider does not trust a caller digest; a registered consent must
            # match the server event digest, checked by the caller that registers it.
            if result.reason == "CONSENT_BINDING_MISMATCH":
                return ConsentResult(ConsentOutcome.CONFLICT, False, record.granting_institution, record.receiving_institution)
            if result.reason == "EXPIRED":
                return ConsentResult(ConsentOutcome.EXPIRED, False, record.granting_institution, record.receiving_institution)
            if result.reason == "REVOKED":
                return ConsentResult(ConsentOutcome.REVOKED, False, record.granting_institution, record.receiving_institution)
            if not result.ok:
                return ConsentResult(ConsentOutcome.INVALID, False, record.granting_institution, record.receiving_institution)
            return ConsentResult(ConsentOutcome.VERIFIED_CROSS_INSTITUTION, True, record.granting_institution, record.receiving_institution)
        if declared.value == "LOCAL_BEHAVIOUR":
            return ConsentResult(ConsentOutcome.VERIFIED_LOCAL, True, event.institution_id, event.institution_id)
        return ConsentResult(ConsentOutcome.MISSING, False)

    def get(self, current_event: CurrentEventRecord | PreAuthEventV2, principal, server_now: datetime, mode) -> ContextResult:
        now = _utc(server_now)
        current = current_event if isinstance(current_event, CurrentEventRecord) else self.lookup(current_event.event_id, current_event.institution_id)
        if current is None:
            raise LookupError("current event is not registered")
        event = current.event
        consent = self._consent_result(current, now)
        expected = self._expected.get(event.institution_id, frozenset({event.institution_id}))
        hub = self._hub.get(event.institution_id, True)
        all_events = tuple(self._history.get(event.institution_id, ()))
        prior = tuple(e for e in all_events if e.event_id != event.event_id and _utc(e.occurred_at) < _utc(event.occurred_at))
        local_prior = [e for e in prior if e.institution_id == event.institution_id]
        coverage = 1.0 if current.attestation_verified and current.local_authorized else 0.0
        if not hub:
            participation = ParticipationResult(Participation.LOCAL_ONLY, True)
        elif consent.outcome == ConsentOutcome.VERIFIED_CROSS_INSTITUTION:
            participation = ParticipationResult(Participation.FULL if expected <= {e.institution_id for e in prior} | {event.institution_id} else Participation.PARTIAL, False)
            coverage = 1.0 if participation.participation == Participation.FULL else 0.75
        elif consent.outcome == ConsentOutcome.VERIFIED_LOCAL:
            participation = ParticipationResult(Participation.FULL if expected == {event.institution_id} else Participation.PARTIAL, False)
        else:
            participation = ParticipationResult(Participation.NONE, False)
        failure = _outcome_failure(consent.outcome)
        if failure == ContextFailure.NONE and _utc(now) - _utc(event.occurred_at) > timedelta(hours=6):
            failure = ContextFailure.INSUFFICIENT_EVIDENCE
        known_age = event.payee_age_bucket.value != "unknown"
        local_sufficient = (
            consent.outcome in (ConsentOutcome.VERIFIED_LOCAL, ConsentOutcome.VERIFIED_CROSS_INSTITUTION)
            and current.attestation_verified and current.local_authorized and failure == ContextFailure.NONE
            and coverage >= 0.75 and (known_age or len({e.event_id for e in local_prior if e.payee_token == event.payee_token}) >= 2)
        )
        if failure == ContextFailure.NONE and not local_sufficient:
            failure = ContextFailure.INSUFFICIENT_HISTORY
        return ContextResult(current, prior, consent, participation, expected, hub, round(coverage, 4), len(local_prior), local_sufficient, f"ctx-{self._snapshot:08d}", failure)


class FixtureContextProvider(VerifiedContextProvider):
    pass
