"""Deterministic synthetic adversarial and degradation fixtures.

These helpers mutate copies of detector-safe events.  They do not represent
attack instructions for a live payment system and never add truth to events.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any, Callable, Mapping, Sequence


def _shift(event: Any, delta: timedelta) -> Any:
    updates = {"occurred_at": event.occurred_at + delta}
    if hasattr(event, "as_of"):
        updates["as_of"] = event.as_of + delta
    return event.model_copy(update=updates)


def delay_hops(events, *, extra_minutes: int = 180):
    """Push a supplied event slice later; retained for the v1 harness."""
    return [_shift(event, timedelta(minutes=extra_minutes)) for event in events]


def delayed_hops_beyond_window(events: Sequence[Any], *, extra_hours: int = 30) -> list[Any]:
    """Move onward legs beyond the motif window while preserving event shape."""
    return [_shift(event, timedelta(hours=extra_hours)) for event in events]


def shift_events_by_role(
    events: Sequence[Any],
    truth_by_event: Mapping[str, Mapping[str, Any]],
    *,
    roles: frozenset[str] = frozenset({"mule_forward", "delayed_hop", "structuring_movement"}),
    delta: timedelta = timedelta(hours=30),
) -> list[Any]:
    """Create a delayed copy using sidecar truth only in the harness."""
    shifted = []
    for event in events:
        row = truth_by_event.get(event.event_id, {})
        shifted.append(_shift(event, delta) if row.get("role") in roles else event)
    return sorted(shifted, key=lambda event: (event.occurred_at, event.event_id))


def fan_in_before_cash_out(events: Sequence[Any], truth_by_event: Mapping[str, Mapping[str, Any]]) -> list[Any]:
    """Return fan-in legs only, before an onward cash-out is observed."""
    return [
        event for event in events
        if truth_by_event.get(event.event_id, {}).get("scenario") == "fanin"
        and truth_by_event.get(event.event_id, {}).get("role") == "fanin_movement"
    ]


def split_value_structuring(events: Sequence[Any], truth_by_event: Mapping[str, Mapping[str, Any]]) -> list[Any]:
    """Return bucketed structuring movement without exposing exact values."""
    return [
        event for event in events
        if truth_by_event.get(event.event_id, {}).get("role") == "structuring_movement"
    ]


def camouflage_lookalikes(events: Sequence[Any], truth_by_event: Mapping[str, Mapping[str, Any]]) -> list[Any]:
    """Build a legitimate-lookalike slice for false-friction measurement."""
    legitimate = {"merchant_burst", "salary_rent_refund", "household", "pass_through", "familiar_payment"}
    return [event for event in events if truth_by_event.get(event.event_id, {}).get("scenario") in legitimate]


def partial_visibility(events: Sequence[Any], institution_id: str) -> list[Any]:
    """Hide partner events without changing or annotating the event objects."""
    return [event for event in events if event.institution_id == institution_id]


def evaluate_policy_degradation(
    events: Sequence[Any],
    truth_by_event: Mapping[str, Mapping[str, Any]],
    score_fn: Callable[[Sequence[Any]], Sequence[str]],
) -> dict[str, Any]:
    """Compare policy recall before/after delayed movement using full stories."""
    base_actions = list(score_fn(events))
    shifted_events = shift_events_by_role(events, truth_by_event)
    shifted_actions = list(score_fn(shifted_events))
    positive = [index for index, event in enumerate(events) if truth_by_event[event.event_id]["label"] == 1]
    shifted_positive = [index for index, event in enumerate(shifted_events) if truth_by_event[event.event_id]["label"] == 1]
    alerted = {"STEP_UP", "ANALYST_REVIEW"}
    before = sum(base_actions[index] in alerted for index in positive)
    after = sum(shifted_actions[index] in alerted for index in shifted_positive)
    denominator = len(positive) or 1
    return {
        "name": "delayed_forward_shift_30h",
        "positive_event_n": len(positive),
        "recall_before": round(before / denominator, 4),
        "recall_after": round(after / (len(shifted_positive) or 1), 4),
        "status": "descriptive_adversarial_degradation",
    }


def adversarial_inventory(events: Sequence[Any], truth_by_event: Mapping[str, Mapping[str, Any]]) -> dict[str, int]:
    return {
        "delayed_hop": sum(truth_by_event[e.event_id]["scenario"] == "delayed_hop" for e in events),
        "fan_in": sum(truth_by_event[e.event_id]["scenario"] == "fanin" for e in events),
        "split_value": sum(truth_by_event[e.event_id]["scenario"] == "split_value" for e in events),
        "lookalike": len(camouflage_lookalikes(events, truth_by_event)),
        "partial_visibility": sum(truth_by_event[e.event_id]["scenario"] == "partial_visibility" for e in events),
    }


def camouflage_note() -> str:
    return (
        "Camouflage in this harness means extra legitimate_lookalike stories in the same stream. "
        "It is not an exploit procedure."
    )


__all__ = [
    "adversarial_inventory",
    "camouflage_lookalikes",
    "camouflage_note",
    "delay_hops",
    "delayed_hops_beyond_window",
    "evaluate_policy_degradation",
    "fan_in_before_cash_out",
    "partial_visibility",
    "shift_events_by_role",
    "split_value_structuring",
]
