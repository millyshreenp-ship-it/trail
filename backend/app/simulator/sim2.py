"""Versioned story-based synthetic corpus for EarlyTrace research.

The generator returns detector-safe ``PreAuthEventV2`` objects and keeps planted
roles/labels in a separate evaluator-only sidecar.  Internal ``acct_`` fixture
references exist only while converting a story and are HMACed before the event
is returned.
"""
from __future__ import annotations

import hashlib
import math
import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from app.models.preauth import ConsentScope, EventSource, PayeeAgeBucket, PreAuthEventV2, SessionContext
from app.security.canonical_json import canonical_json_bytes
from app.security.tokens import TrustedReferenceAdapter, TokenService
from app.simulator.scam_patterns import preauth_story_events

SIM2_VERSION = "earlytrace-sim-2"
SCENARIO_REVISION = "lookalikes-v2"
SIM2_LABEL_RULE = (
    "label=1 exactly when role is one of social_engineering_preauth, "
    "mule_forward, fanout_movement, fanin_movement, delayed_hop, or "
    "structuring_movement; declared legitimate roles are label=0. "
    "Truth is generated independently and is never a detector feature."
)

SCENARIO_KINDS = (
    "familiar_payment",
    "new_beneficiary",
    "rapid_forward",
    "fanout",
    "fanin",
    "delayed_hop",
    "split_value",
    "partial_visibility",
    "merchant_burst",
    "salary_rent_refund",
    "household",
    "safe_new_payee",
    "pass_through",
)

LEGITIMATE_ROLES = frozenset({"legitimate_lookalike"})
POSITIVE_ROLES = frozenset({
    "social_engineering_preauth",
    "mule_forward",
    "fanout_movement",
    "fanin_movement",
    "delayed_hop",
    "structuring_movement",
})

# The longest declared story is the 60-day salary/refund story plus its
# final 26-hour deferred event. It is deliberately explicit and versioned.
MAX_DECLARED_STORY_DURATION_SECONDS = 60 * 86400 + 26 * 3600
STORY_GUARD_SECONDS = MAX_DECLARED_STORY_DURATION_SECONDS + 24 * 3600
_INSTITUTION_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,32}$")

DEFAULT_SCENARIO_MIXTURE = {
    "familiar_payment": 1 / 13,
    "new_beneficiary": 1 / 13,
    "rapid_forward": 1 / 13,
    "fanout": 1 / 13,
    "fanin": 1 / 13,
    "delayed_hop": 1 / 13,
    "split_value": 1 / 13,
    "partial_visibility": 1 / 13,
    "merchant_burst": 1 / 13,
    "salary_rent_refund": 1 / 13,
    "household": 1 / 13,
    "safe_new_payee": 1 / 13,
    "pass_through": 1 / 13,
}


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("story timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class CorpusConfig:
    """Validated controls for one deterministic sim-2 corpus."""

    seed: int = 7
    calendar_days: int = 180
    story_count: int | None = 3000
    volume_target: int | None = None
    institutions: tuple[str, ...] = ("BANK_A", "BANK_B", "BANK_C")
    scenario_mixture: Mapping[str, float] = field(
        default_factory=lambda: dict(DEFAULT_SCENARIO_MIXTURE)
    )
    held_out_morphology: str | None = "split_value"
    # ``mixture`` is a convenience spelling for CLI/config callers.  It is
    # normalised into scenario_mixture and is not a second control.
    mixture: Mapping[str, float] | None = None

    def __post_init__(self) -> None:
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("seed must be an integer")
        if isinstance(self.calendar_days, bool) or not isinstance(self.calendar_days, int) or self.calendar_days <= 0:
            raise ValueError("calendar_days must be a positive integer")
        if self.story_count is None and self.volume_target is None:
            raise ValueError("one of story_count or volume_target is required")
        if self.story_count is not None:
            if isinstance(self.story_count, bool) or not isinstance(self.story_count, int) or self.story_count <= 0:
                raise ValueError("story_count must be a positive integer")
        if self.volume_target is not None:
            if isinstance(self.volume_target, bool) or not isinstance(self.volume_target, int) or self.volume_target <= 0:
                raise ValueError("volume_target must be a positive integer")
            if self.story_count is not None:
                raise ValueError("story_count and volume_target are mutually exclusive")
        institutions = tuple(self.institutions)
        if len(institutions) < 2:
            raise ValueError("at least two institutions are required")
        if len(set(institutions)) != len(institutions):
            raise ValueError("institution IDs must be unique")
        if institutions != tuple(sorted(institutions)):
            raise ValueError("institution IDs must be sorted")
        if any(not isinstance(value, str) or not _INSTITUTION_RE.fullmatch(value) for value in institutions):
            raise ValueError("institution IDs have an invalid format")
        object.__setattr__(self, "institutions", institutions)

        base_mixture = DEFAULT_SCENARIO_MIXTURE if self.scenario_mixture is None else self.scenario_mixture
        selected_source = self.mixture if self.mixture is not None else base_mixture
        if not isinstance(selected_source, Mapping):
            raise ValueError("scenario mixture must be a mapping")
        selected = dict(selected_source)
        unknown = set(selected) - set(SCENARIO_KINDS)
        if unknown:
            raise ValueError(f"unknown scenario mixture key: {sorted(unknown)[0]}")
        if set(selected) != set(SCENARIO_KINDS):
            missing = set(SCENARIO_KINDS) - set(selected)
            raise ValueError(f"scenario mixture is missing: {sorted(missing)[0]}")
        if any(
            isinstance(weight, bool)
            or not isinstance(weight, (int, float))
            or not math.isfinite(weight)
            or weight < 0
            for weight in selected.values()
        ):
            raise ValueError("scenario mixture weights must be finite and nonnegative")
        if not math.isclose(sum(selected.values()), 1.0, rel_tol=0.0, abs_tol=1e-9):
            raise ValueError("scenario mixture weights must sum to 1.0")
        if not any(weight > 0 for weight in selected.values()):
            raise ValueError("scenario mixture must contain a positive weight")
        if self.held_out_morphology is not None and self.held_out_morphology not in SCENARIO_KINDS:
            raise ValueError("unknown held_out_morphology")
        if self.held_out_morphology is not None and selected.get(self.held_out_morphology, 0.0) <= 0:
            raise ValueError("held_out_morphology must have a positive mixture weight")
        normalised = {name: float(selected[name]) for name in SCENARIO_KINDS}
        object.__setattr__(self, "scenario_mixture", normalised)
        object.__setattr__(self, "mixture", None)

    @property
    def requested_story_count(self) -> int | None:
        return self.story_count

    def as_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "calendar_days": self.calendar_days,
            "story_count": self.story_count,
            "volume_target": self.volume_target,
            "institutions": list(self.institutions),
            "scenario_mixture": dict(self.scenario_mixture),
            "held_out_morphology": self.held_out_morphology,
            "scenario_revision": SCENARIO_REVISION,
            "split_fractions": {"train": 0.60, "calibration": 0.20, "test": 0.20},
            "max_declared_story_duration_seconds": MAX_DECLARED_STORY_DURATION_SECONDS,
            "guard_seconds": STORY_GUARD_SECONDS,
        }


def _partition_counts(story_count: int) -> tuple[int, int, int]:
    train = int(story_count * 0.60)
    calibration = int(story_count * 0.20)
    # The remainder makes the three complete-story partitions exhaustive.
    return train, calibration, story_count - train - calibration


def _sample_kind(rng: random.Random, mixture: Mapping[str, float], *, exclude: str | None = None) -> str:
    choices = [(name, weight) for name, weight in mixture.items() if name != exclude and weight > 0]
    total = sum(weight for _name, weight in choices)
    if total <= 0:
        raise ValueError("scenario mixture has no eligible stories")
    needle = rng.random() * total
    for name, weight in choices:
        needle -= weight
        if needle <= 0:
            return name
    return choices[-1][0]


def _story_start(
    index: int,
    *,
    origin: datetime,
    span_seconds: int,
    counts: tuple[int, int, int],
    guard_seconds: int,
    rng: random.Random,
) -> datetime:
    """Place each partition's starts behind a max-duration guard gap."""
    train_n, calibration_n, test_n = counts
    if index < train_n:
        partition_index, local_index, partition_count = 0, index, train_n
    elif index < train_n + calibration_n:
        partition_index, local_index, partition_count = 1, index - train_n, calibration_n
    else:
        partition_index, local_index, partition_count = 2, index - train_n - calibration_n, test_n
    train_span = int(span_seconds * 0.60)
    calibration_span = int(span_seconds * 0.20)
    spans = (train_span, calibration_span, span_seconds - train_span - calibration_span)
    starts = (0, train_span + guard_seconds, train_span + calibration_span + 2 * guard_seconds)
    fraction = (local_index + rng.random()) / max(1, partition_count)
    return origin + timedelta(seconds=starts[partition_index] + int(fraction * spans[partition_index]))


def _role_for(kind: str, index: int, old_role: str) -> str:
    if kind == "new_beneficiary":
        return "social_engineering_preauth"
    if kind == "rapid_forward":
        return "social_engineering_preauth" if index == 0 else "mule_forward"
    if kind == "fanout":
        return "social_engineering_preauth" if index == 0 else "fanout_movement"
    if kind == "fanin":
        return "fanin_movement"
    if kind == "delayed_hop":
        return "social_engineering_preauth" if index == 0 else "delayed_hop"
    if kind == "split_value":
        return "social_engineering_preauth" if index == 0 else "structuring_movement"
    if kind == "partial_visibility":
        return "social_engineering_preauth" if index == 0 else "mule_forward"
    if old_role in POSITIVE_ROLES:
        return old_role
    return "legitimate_lookalike"


def _scenario_for(kind: str, old_scenario: str) -> str:
    if old_scenario in {"salary", "rent", "refund"}:
        return old_scenario
    if old_scenario == "FAMILIAR_PAYEE":
        return "familiar_payment"
    return kind


def _scenario_event(
    raw: Any,
    *,
    event_id: str,
    trace_id: str,
    idempotency_key: str,
    institution_map: Mapping[str, str],
    tokens: TrustedReferenceAdapter,
) -> PreAuthEventV2:
    source = tokens.to_live_token(raw.source_token, "earlytrace-sim-2", "v1")
    payee = tokens.to_live_token(raw.payee_token, "earlytrace-sim-2", "v1")
    raw_institution = raw.institution_id
    institution = institution_map.get(raw_institution, institution_map["BANK_A"])
    consent = raw.consent_scope
    if not isinstance(consent, ConsentScope):
        consent = ConsentScope(str(getattr(consent, "value", consent)))
    return PreAuthEventV2(
        schema_version="earlytrace.preauth.v2",
        event_id=event_id,
        occurred_at=_utc(raw.occurred_at),
        as_of=_utc(raw.occurred_at),
        institution_id=institution,
        event_source=EventSource.SYNTHETIC_GENERATOR,
        rail=str(raw.rail),
        source_token=source,
        payee_token=payee,
        amount_bucket=str(raw.amount_bucket),
        payee_age_bucket=raw.payee_age_bucket,
        session_context=raw.session_context,
        consent_scope=consent,
        trace_id=trace_id,
        idempotency_key=idempotency_key,
    )


def generate_sim2_corpus(config: CorpusConfig | None = None, **overrides: Any) -> dict[str, Any]:
    """Generate complete, story-disjoint sim-2 events and truth sidecar.

    ``overrides`` mirrors :class:`CorpusConfig` for small local smoke calls.
    The returned event objects contain no story, role, scenario, or label data.
    """
    if config is not None and overrides:
        raise ValueError("config and keyword overrides cannot be combined")
    config = config or CorpusConfig(**overrides)
    rng = random.Random(config.seed)
    origin = datetime(2026, 1, 1, 8, 0, tzinfo=timezone.utc)
    story_target = config.story_count
    events: list[PreAuthEventV2] = []
    truth_by_event: dict[str, dict[str, Any]] = {}
    stories: list[dict[str, Any]] = []
    counts = _partition_counts(story_target) if story_target is not None else None
    generated_stories = 0
    generated_event_count = 0
    token_service = TokenService(b"earlytrace-sim-2-local-key-v1")
    token_adapter = TrustedReferenceAdapter(token_service)
    institution_map = {
        "BANK_A": config.institutions[0],
        "BANK_B": config.institutions[min(1, len(config.institutions) - 1)],
        "BANK_C": config.institutions[min(2, len(config.institutions) - 1)],
        "WALLET_W": config.institutions[-1],
    }
    span_seconds = config.calendar_days * 86400
    max_stories = story_target if story_target is not None else 100_000

    while generated_stories < max_stories and (
        config.volume_target is None or generated_event_count < config.volume_target
    ):
        if story_target is not None:
            train_n, cal_n, _test_n = counts or (0, 0, 0)
            test_start = train_n + cal_n
            excluded = config.held_out_morphology if generated_stories < test_start else None
        else:
            # Volume mode has no hidden event truncation; reserve the held-out
            # family for the final fifth of complete stories.
            excluded = config.held_out_morphology if generated_stories % 5 != 4 else None
        if config.held_out_morphology is not None and story_target is not None and generated_stories == test_start:
            kind = config.held_out_morphology
        else:
            kind = _sample_kind(rng, config.scenario_mixture, exclude=excluded)
        if story_target is not None:
            start = _story_start(
                generated_stories,
                origin=origin,
                span_seconds=span_seconds,
                counts=counts or (0, 0, 0),
                guard_seconds=STORY_GUARD_SECONDS,
                rng=rng,
            )
        else:
            slot = (generated_stories + rng.random()) / max(1, max_stories)
            start = origin + timedelta(seconds=min(span_seconds - 1, int(slot * span_seconds)))
        story_seed = rng.randrange(1, 9_000_000)
        raw_events, raw_labels, _ = preauth_story_events(
            kind, seed=story_seed, start=start, seq=generated_stories * 1000 + 1
        )
        story_id = f"story_s2_{generated_stories:06d}"
        story_event_ids: list[str] = []
        for local_index, raw in enumerate(raw_events):
            event_id = f"evt_s2_{generated_stories:06d}_{local_index:03d}"
            event = _scenario_event(
                raw,
                event_id=event_id,
                trace_id=f"trace_s2_{generated_stories:06d}_{local_index:03d}",
                idempotency_key=f"idem_s2_{generated_stories:06d}_{local_index:03d}",
                institution_map=institution_map,
                tokens=token_adapter,
            )
            old_meta = raw_labels.get(raw.event_id, {})
            if kind == "safe_new_payee" and story_seed % 3 == 0:
                event = event.model_copy(update={"session_context": SessionContext("URGENT_SOCIAL_ENGINEERING"), "amount_bucket": "50k_100k"})
            elif kind in {"new_beneficiary", "rapid_forward", "fanout", "delayed_hop", "split_value", "partial_visibility"} and local_index == 0 and story_seed % 3 == 0:
                event = event.model_copy(update={"session_context": SessionContext("ROUTINE"), "payee_age_bucket": PayeeAgeBucket("90d_plus")})
            role = _role_for(kind, local_index, str(old_meta.get("role", "")))
            scenario = _scenario_for(kind, str(old_meta.get("scenario", "")))
            label = 1 if role in POSITIVE_ROLES else 0
            events.append(event)
            story_event_ids.append(event.event_id)
            truth_by_event[event.event_id] = {
                "event_id": event.event_id,
                "story_id": story_id,
                "scenario": scenario,
                "role": role,
                "label": label,
                "label_rule": SIM2_LABEL_RULE,
                "provenance": "synthetic-story-sidecar",
            }
        stories.append({
            "story_id": story_id,
            "scenario": kind,
            "start": _utc(start).isoformat(),
            "event_ids": story_event_ids,
        })
        generated_stories += 1
        generated_event_count += len(raw_events)

    if not stories:
        raise ValueError("sim-2 generation produced no complete stories")
    stories.sort(key=lambda row: (row["start"], row["story_id"]))
    events.sort(key=lambda event: (_utc(event.occurred_at), event.event_id))
    train_n, cal_n, test_n = _partition_counts(len(stories))
    for index, story in enumerate(stories):
        story["partition"] = "train" if index < train_n else "calibration" if index < train_n + cal_n else "test"
    test_event_ids = {
        event_id for story in stories if story["partition"] == "test" for event_id in story["event_ids"]
    }
    test_times = [event.occurred_at for event in events if event.event_id in test_event_ids]
    test_end = (
        origin + timedelta(seconds=span_seconds + 2 * STORY_GUARD_SECONDS + MAX_DECLARED_STORY_DURATION_SECONDS)
        if story_target is not None
        else origin + timedelta(seconds=span_seconds + STORY_GUARD_SECONDS)
    )
    if test_times and max(test_times) >= test_end:
        raise AssertionError("sim-2 test event is outside the guarded test boundary")
    nominal_train_end = origin + timedelta(seconds=int(span_seconds * 0.60))
    nominal_cal_end = origin + timedelta(seconds=int(span_seconds * 0.80))
    event_payload = [event.model_dump(mode="json") for event in events]
    truth_payload = [truth_by_event[event_id] for event_id in sorted(truth_by_event)]
    story_counts = {part: sum(1 for story in stories if story["partition"] == part) for part in ("train", "calibration", "test")}
    event_counts = {
        part: sum(len(story["event_ids"]) for story in stories if story["partition"] == part)
        for part in ("train", "calibration", "test")
    }
    scenario_counts: dict[str, int] = {name: 0 for name in SCENARIO_KINDS}
    for story in stories:
        scenario_counts[story["scenario"]] += 1
    manifest = {
        "generator_version": SIM2_VERSION,
        "scenario_revision": SCENARIO_REVISION,
        "scenario_name": "story_based_payment_events",
        "data_status": "synthetic",
        "provenance": "Synthetic payment-event simulator; not customer, UPI, bank, or NPCI data.",
        "licence": "repository-generated synthetic events; no third-party dataset",
        "seed": config.seed,
        "configuration": config.as_dict(),
        "held_out_morphology": config.held_out_morphology,
        "requested_story_count": config.story_count,
        "actual_story_count": len(stories),
        "requested_event_target": config.volume_target,
        "actual_event_count": len(events),
        "event_count": len(events),
        "actual_scenario_story_counts": scenario_counts,
        "story_counts": story_counts,
        "event_counts": event_counts,
        "max_declared_story_duration_seconds": MAX_DECLARED_STORY_DURATION_SECONDS,
        "guard_seconds": STORY_GUARD_SECONDS,
        "split_boundaries": {
            "origin": origin.isoformat(),
            "nominal_train_end": nominal_train_end.isoformat(),
            "nominal_calibration_end": nominal_cal_end.isoformat(),
            "nominal_test_end": (origin + timedelta(seconds=span_seconds)).isoformat(),
            "train_end": nominal_train_end.isoformat(),
            "calibration_end": nominal_cal_end.isoformat(),
            "effective_train_end": (origin + timedelta(seconds=int(span_seconds * 0.60) + STORY_GUARD_SECONDS)).isoformat(),
            "effective_calibration_end": (origin + timedelta(seconds=int(span_seconds * 0.80) + 2 * STORY_GUARD_SECONDS)).isoformat(),
            "test_end": test_end.isoformat(),
            "effective_test_end": test_end.isoformat(),
            "max_test_event_at": max(test_times).isoformat() if test_times else None,
            "assertion": "max(test.occurred_at) < test_end",
            "scheme": "complete stories by ordered start: 60/20/20; guarded test end",
        },
        "event_checksum": _sha256(event_payload),
        "label_checksum": _sha256(truth_payload),
        "truth_checksum": _sha256(truth_payload),
        "checksums": {
            "events": _sha256(event_payload),
            "truth_by_event": _sha256(truth_payload),
        },
        "truth_sidecar": "truth_by_event.json; evaluator-only and never a detector input",
        "feature_contract": "motif.v2",
        "external_datasets": [],
        "neural_model_trained": False,
    }
    return {
        "name": SIM2_VERSION,
        "seed": config.seed,
        "events": events,
        "truth_by_event": truth_by_event,
        "stories": stories,
        "manifest": manifest,
    }


# Names that make the versioned path discoverable without changing the v1 API.
generate_preauth_corpus_v2 = generate_sim2_corpus
generate_story_corpus = generate_sim2_corpus


__all__ = [
    "CorpusConfig",
    "DEFAULT_SCENARIO_MIXTURE",
    "LEGITIMATE_ROLES",
    "POSITIVE_ROLES",
    "SCENARIO_KINDS",
    "SIM2_LABEL_RULE",
    "SIM2_VERSION",
    "STORY_GUARD_SECONDS",
    "generate_sim2_corpus",
    "generate_preauth_corpus_v2",
    "generate_story_corpus",
]
