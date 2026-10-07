"""Evaluator-only planted truth for the sim-2 story corpus.

This module is intentionally outside ``app.detection``.  Scorers receive
server-owned event/context objects and are joined to this sidecar only after a
prediction has been produced.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from app.security.canonical_json import canonical_json_bytes

POSITIVE_ROLES = frozenset({
    "social_engineering_preauth",
    "mule_forward",
    "fanout_movement",
    "fanin_movement",
    "delayed_hop",
    "structuring_movement",
})


@dataclass(frozen=True)
class TruthLabel:
    event_id: str
    story_id: str
    scenario: str
    role: str
    label: int
    label_rule: str
    provenance: str = "synthetic-story-sidecar"

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "story_id": self.story_id,
            "scenario": self.scenario,
            "role": self.role,
            "label": self.label,
            "label_rule": self.label_rule,
            "provenance": self.provenance,
        }


def label_for_role(role: str) -> int:
    return int(role in POSITIVE_ROLES)


def validate_truth_by_event(truth_by_event: Mapping[str, Mapping[str, Any]]) -> None:
    for event_id, row in truth_by_event.items():
        if row.get("event_id") != event_id:
            raise ValueError("truth sidecar event ID mismatch")
        label = row.get("label")
        if label not in (0, 1) or label != label_for_role(str(row.get("role", ""))):
            raise ValueError("truth sidecar label does not match its role")
        if not row.get("story_id") or not row.get("scenario"):
            raise ValueError("truth sidecar requires story and scenario")


def truth_checksum(truth_by_event: Mapping[str, Mapping[str, Any]]) -> str:
    validate_truth_by_event(truth_by_event)
    rows = [dict(truth_by_event[event_id]) for event_id in sorted(truth_by_event)]
    return hashlib.sha256(canonical_json_bytes(rows)).hexdigest()


def write_truth_sidecar(path: str | Path, truth_by_event: Mapping[str, Mapping[str, Any]]) -> str:
    checksum = truth_checksum(truth_by_event)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {event_id: dict(truth_by_event[event_id]) for event_id in sorted(truth_by_event)}
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return checksum


__all__ = [
    "POSITIVE_ROLES",
    "TruthLabel",
    "label_for_role",
    "validate_truth_by_event",
    "truth_checksum",
    "write_truth_sidecar",
]
