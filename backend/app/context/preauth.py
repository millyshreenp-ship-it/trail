"""Allowlisted source and consent primitives for EarlyTrace v2.

There are deliberately no external connectors in this module.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol

from app.models.preauth import ConsentOutcome, EventSource, Participation

DISABLED_EXTERNAL_SOURCES = frozenset({"EXTERNAL_BANK", "BANK", "NPCI", "UPI_SWITCH", "CLOUD"})
ALLOWED_EVENT_SOURCES = frozenset(item.value for item in EventSource)


class SourceRejected(ValueError):
    pass


def require_event_source(source: EventSource | str) -> EventSource:
    value = source.value if isinstance(source, EventSource) else str(source)
    if value not in ALLOWED_EVENT_SOURCES:
        raise SourceRejected("event source is not enabled")
    return EventSource(value)


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


class CurrentEventStore(Protocol):
    def get(self, event_id: str, institution_id: str): ...


class ContextProvider(Protocol):
    def get(self, current_event, principal, server_now: datetime, mode): ...


@dataclass(frozen=True)
class ContextResult:
    consent: ConsentResult
    participation: ParticipationResult
    local_sufficient: bool
    context_snapshot_id: str | None = None
    failure_code: str | None = None
