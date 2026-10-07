"""Leakage-safe splits for the synthetic EarlyTrace corpus."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


def _token_bucket(token: str) -> int:
    digest = hmac.new(b"earlytrace-split-v1", token.encode(), hashlib.sha256).hexdigest()
    return int(digest[:8], 16)


def temporal_masks(events, train_end: datetime, cal_end: datetime) -> dict[str, list]:
    train, cal, test = [], [], []
    for e in events:
        if e.occurred_at < train_end:
            train.append(e)
        elif e.occurred_at < cal_end:
            cal.append(e)
        else:
            test.append(e)
    return {"train": train, "calibration": cal, "test": test}


def inductive_holdout(events, *, modulus: int = 5, remainder: int = 0) -> tuple[list, list]:
    """Hold out events whose source or payee token falls in a stable bucket."""
    train, test = [], []
    for e in events:
        held = (_token_bucket(e.source_token) % modulus == remainder) or (
            _token_bucket(e.payee_token) % modulus == remainder
        )
        (test if held else train).append(e)
    return train, test


def open_set_split(events, labels: dict, *, held_out_scenario: str = "split_value") -> tuple[list, list]:
    train, test = [], []
    for e in events:
        scenario = labels.get(e.event_id, {}).get("scenario")
        (test if scenario == held_out_scenario else train).append(e)
    return train, test


def legitimate_stress(events, labels: dict) -> list:
    keep = {"merchant", "household", "rent", "salary", "refund", "safe_new_payee", "pass_through", "familiar_payment"}
    return [e for e in events if labels.get(e.event_id, {}).get("scenario") in keep]


def assert_no_future(events, as_of: datetime) -> None:
    for e in events:
        if e.occurred_at > as_of:
            raise AssertionError("future event leaked into an as_of window")


def history_before(events, current) -> tuple:
    """Return only strict event-time history for one subject event."""
    current_time = current.occurred_at
    return tuple(
        event for event in events
        if event.event_id != current.event_id and event.occurred_at < current_time
    )


@dataclass(frozen=True)
class StorySplit:
    """A complete-story partition; no story ID is shared across partitions."""

    name: str
    story_ids: tuple[str, ...]
    events: tuple[Any, ...]
    story_records: tuple[dict[str, Any], ...]
    guard_seconds: int

    @property
    def event_ids(self) -> tuple[str, ...]:
        return tuple(event.event_id for event in self.events)

    @property
    def start(self) -> datetime | None:
        starts = [datetime.fromisoformat(row["start"]) for row in self.story_records if row.get("start")]
        return min(starts) if starts else None

    @property
    def end(self) -> datetime | None:
        times = [event.occurred_at for event in self.events]
        return max(times) if times else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "story_ids": list(self.story_ids),
            "story_count": len(self.story_ids),
            "event_count": len(self.events),
            "guard_seconds": self.guard_seconds,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
        }


def _story_partition_counts(count: int) -> tuple[int, int, int]:
    train = int(count * 0.60)
    calibration = int(count * 0.20)
    return train, calibration, count - train - calibration


def split_complete_stories(
    events,
    truth_by_event: Mapping[str, Mapping[str, Any]],
    *,
    stories: list[Mapping[str, Any]] | None = None,
    guard_seconds: int = 0,
) -> dict[str, StorySplit]:
    """Split complete stories in start order using exact 60/20/20 counts.

    A story is the atomic split unit.  The event sidecar is used only to join
    event IDs to story IDs; it is never passed to a feature builder.
    """
    by_event = {event.event_id: event for event in events}
    grouped: dict[str, list[str]] = {}
    scenario_by_story: dict[str, str] = {}
    for event_id, truth in truth_by_event.items():
        if event_id not in by_event:
            raise ValueError("truth sidecar contains an unknown event")
        story_id = str(truth["story_id"])
        grouped.setdefault(story_id, []).append(event_id)
        scenario_by_story[story_id] = str(truth.get("scenario", ""))
    if set(by_event) != set(truth_by_event):
        raise ValueError("every valid event must have exactly one truth row")
    records_by_id: dict[str, dict[str, Any]] = {}
    for row in stories or []:
        story_id = str(row["story_id"])
        records_by_id[story_id] = dict(row)
    records = []
    for story_id, event_ids in grouped.items():
        ordered_events = sorted((by_event[event_id] for event_id in event_ids), key=lambda event: (event.occurred_at, event.event_id))
        record = records_by_id.get(story_id, {
            "story_id": story_id,
            "scenario": scenario_by_story.get(story_id, ""),
            "start": ordered_events[0].occurred_at.isoformat(),
            "event_ids": [event.event_id for event in ordered_events],
        })
        declared = set(record.get("event_ids", event_ids))
        if declared != set(event_ids):
            raise ValueError("story record is incomplete")
        record["event_ids"] = [event.event_id for event in ordered_events]
        records.append(record)
    records.sort(key=lambda row: (row["start"], row["story_id"]))
    train_n, calibration_n, _test_n = _story_partition_counts(len(records))
    names = ("train", "calibration", "test")
    partitions: dict[str, StorySplit] = {}
    for index, name in enumerate(names):
        lo = 0 if index == 0 else train_n if index == 1 else train_n + calibration_n
        hi = train_n if index == 0 else train_n + calibration_n if index == 1 else len(records)
        selected = records[lo:hi]
        selected_ids = tuple(str(row["story_id"]) for row in selected)
        selected_events = tuple(
            event for row in selected for event in sorted(
                (by_event[event_id] for event_id in row["event_ids"]),
                key=lambda event: (event.occurred_at, event.event_id),
            )
        )
        partitions[name] = StorySplit(name, selected_ids, selected_events, tuple(selected), guard_seconds)
    all_story_ids = [story_id for split in partitions.values() for story_id in split.story_ids]
    if len(all_story_ids) != len(set(all_story_ids)) or set(all_story_ids) != set(grouped):
        raise AssertionError("complete-story partitions overlap or omit a story")
    return partitions


# Compatibility aliases for callers that describe the same operation as a
# temporal story mask rather than a split object.
temporal_story_masks = split_complete_stories
complete_story_temporal_splits = split_complete_stories
