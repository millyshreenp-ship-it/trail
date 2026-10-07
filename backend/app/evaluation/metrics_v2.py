"""UNKNOWN-aware research metrics for complete-story sim-2 runs."""
from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from statistics import mean
from typing import Any, Callable, Mapping, Sequence


def _legacy(name: str):
    from app.evaluation import metrics as legacy_metrics
    return getattr(legacy_metrics, name)


def binary_counts(*args, **kwargs):
    return _legacy("binary_counts")(*args, **kwargs)


def expected_calibration_error(*args, **kwargs):
    return _legacy("expected_calibration_error")(*args, **kwargs)


def macro_f1(*args, **kwargs):
    return _legacy("macro_f1")(*args, **kwargs)


def percentile(*args, **kwargs):
    return _legacy("percentile")(*args, **kwargs)


def pr_auc(*args, **kwargs):
    return _legacy("pr_auc")(*args, **kwargs)


def _rows(
    scores: Sequence[float | None],
    labels: Sequence[int],
    *,
    event_keys: Sequence[tuple[Any, str]] | None = None,
    actions: Sequence[str] | None = None,
) -> tuple[list[tuple[float, int, int, tuple[Any, str]]], int]:
    if len(scores) != len(labels):
        raise ValueError("scores and labels must have equal length")
    if actions is not None and len(actions) != len(labels):
        raise ValueError("actions and labels must have equal length")
    keys = event_keys or [(index, str(index)) for index in range(len(labels))]
    if len(keys) != len(labels):
        raise ValueError("event keys and labels must have equal length")
    valid: list[tuple[float, int, int, tuple[Any, str]]] = []
    unknown = 0
    for index, (score, label, key) in enumerate(zip(scores, labels, keys)):
        if label not in (0, 1):
            raise ValueError("labels must be binary")
        if score is None or (actions is not None and actions[index] == "UNKNOWN"):
            unknown += 1
            continue
        valid.append((float(score), int(label), index, key))
    return valid, unknown


def budget_metrics(
    scores: Sequence[float | None],
    labels: Sequence[int],
    *,
    alerts_per_thousand: float = 20.0,
    event_keys: Sequence[tuple[Any, str]] | None = None,
    actions: Sequence[str] | None = None,
    positive_story_count: int | None = None,
) -> dict[str, Any]:
    """Compute a floor-budget metric without ranking or filling UNKNOWN rows."""
    if alerts_per_thousand < 0 or alerts_per_thousand > 1000:
        raise ValueError("alerts_per_thousand must be between 0 and 1000")
    valid, unknown_n = _rows(scores, labels, event_keys=event_keys, actions=actions)
    eligible_n = len(labels)
    budget_slots = int(eligible_n * alerts_per_thousand / 1000.0)
    ranked = sorted(valid, key=lambda row: (-row[0], row[3][0], row[3][1]))
    selected = ranked[:budget_slots]
    tp = sum(row[1] for row in selected)
    positives = sum(labels)
    selected_alerts = len(selected)
    unfilled_slots = max(0, budget_slots - selected_alerts)
    if budget_slots == 0:
        status = "no_budget_slot"
    elif selected_alerts < budget_slots:
        status = "unfilled_slots"
    elif unknown_n:
        status = "unknown_rows_present"
    elif budget_slots < 20 or (positive_story_count is not None and positive_story_count < 30):
        status = "insufficient_budget_support"
    else:
        status = "supported"
    return {
        "alerts_per_thousand": alerts_per_thousand,
        "eligible_n": eligible_n,
        "scored_n": len(valid),
        "unknown_n": unknown_n,
        "budget_slots": budget_slots,
        "selected_alerts": selected_alerts,
        "selected_event_ids": [row[3][1] for row in selected],
        "unfilled_slots": unfilled_slots,
        "status": status,
        "alert_count": selected_alerts,
        "precision": round(tp / selected_alerts, 4) if selected_alerts else None,
        "recall": round(tp / positives, 4) if positives else 0.0,
        "budget_support_status": status,
        "support_warning": (
            "The declared budget has fewer than 20 alert slots; precision is descriptive."
            if budget_slots < 20 else None
        ),
    }


precision_recall_at_budget_v2 = budget_metrics


def _scored_metric_domain(scores, labels, actions=None) -> dict[str, Any]:
    valid, unknown_n = _rows(scores, labels, actions=actions)
    return {
        "eligible_n": len(labels),
        "scored_n": len(valid),
        "unknown_n": unknown_n,
        "status": "complete" if not unknown_n else "unscored_rows_not_silently_filtered",
    }


def pr_auc_unknown(scores: Sequence[float | None], labels: Sequence[int], *, actions=None) -> dict[str, Any]:
    valid, unknown_n = _rows(scores, labels, actions=actions)
    domain = _scored_metric_domain(scores, labels, actions)
    if unknown_n:
        return {"value": None, **domain, "reason": "eligible rows are unscored"}
    return {"value": pr_auc([row[0] for row in valid], [row[1] for row in valid]), **domain}


def brier_unknown(scores: Sequence[float | None], labels: Sequence[int], *, actions=None) -> dict[str, Any]:
    valid, unknown_n = _rows(scores, labels, actions=actions)
    domain = _scored_metric_domain(scores, labels, actions)
    if unknown_n:
        return {"value": None, **domain, "reason": "eligible rows are unscored"}
    if not valid:
        return {"value": None, **domain, "reason": "no scored rows"}
    return {"value": round(sum((score - label) ** 2 for score, label, _index, _key in valid) / len(valid), 4), **domain}


def ece_unknown(
    scores: Sequence[float | None], labels: Sequence[int], *, actions=None, bins: int = 10
) -> dict[str, Any]:
    valid, unknown_n = _rows(scores, labels, actions=actions)
    domain = _scored_metric_domain(scores, labels, actions)
    if unknown_n:
        return {"value": None, "reliability": [], **domain, "reason": "eligible rows are unscored"}
    curve = expected_calibration_error([row[0] for row in valid], [row[1] for row in valid], bins=bins)
    return {"value": curve["ece"], "reliability": curve["reliability"], **domain}


def grouped_error_unknown(
    predictions: Sequence[int | None], labels: Sequence[int], groups: Sequence[str]
) -> dict[str, Any]:
    if not (len(predictions) == len(labels) == len(groups)):
        raise ValueError("predictions, labels, and groups must have equal length")
    grouped: dict[str, list[tuple[int, int]]] = defaultdict(list)
    unknown: dict[str, int] = defaultdict(int)
    for prediction, label, group in zip(predictions, labels, groups):
        if prediction is None:
            unknown[group] += 1
        else:
            grouped[group].append((int(prediction), int(label)))
    output: dict[str, Any] = {}
    for group in sorted(set(groups)):
        rows = grouped[group]
        counts = binary_counts([row[0] for row in rows], [row[1] for row in rows]) if rows else None
        output[group] = {
            "n": len(rows) + unknown[group],
            "scored_n": len(rows),
            "unknown_n": unknown[group],
            "fpr": counts["fpr"] if counts else None,
            "fnr": counts["fnr"] if counts else None,
            "status": "complete" if not unknown[group] else "unknown_rows_present",
        }
    return output


def macro_f1_unknown(predictions: Sequence[int | None], labels: Sequence[int]) -> dict[str, Any]:
    if len(predictions) != len(labels):
        raise ValueError("predictions and labels must have equal length")
    scored = [(int(prediction), int(label)) for prediction, label in zip(predictions, labels) if prediction is not None]
    unknown_n = len(labels) - len(scored)
    return {
        "value": macro_f1([row[0] for row in scored], [row[1] for row in scored]) if scored else None,
        "eligible_n": len(labels),
        "scored_n": len(scored),
        "unknown_n": unknown_n,
        "status": "complete" if not unknown_n else "unknown_rows_present",
    }


def coverage_metrics(actions: Sequence[str], labels: Sequence[int], scores: Sequence[float | None]) -> dict[str, Any]:
    if not (len(actions) == len(labels) == len(scores)):
        raise ValueError("actions, labels, and scores must have equal length")
    unknown = [index for index, action in enumerate(actions) if action == "UNKNOWN" or scores[index] is None]
    scored = [index for index in range(len(labels)) if index not in set(unknown)]
    errors = sum(1 for index in scored if (float(scores[index]) >= 0.5) != bool(labels[index]))
    return {
        "eligible_n": len(labels),
        "scored_n": len(scored),
        "unknown_n": len(unknown),
        "unknown_rate": round(len(unknown) / len(labels), 4) if labels else 0.0,
        "coverage": round(len(scored) / len(labels), 4) if labels else 0.0,
        "selective_risk": round(errors / len(scored), 4) if scored else None,
    }


def story_detection_metrics(
    events: Sequence[Any],
    truth_by_event: Mapping[str, Mapping[str, Any]],
    actions: Sequence[str],
    *,
    scores: Sequence[float | None] | None = None,
    b0_threshold: float | None = None,
) -> dict[str, Any]:
    if len(events) != len(actions) or (scores is not None and len(events) != len(scores)):
        raise ValueError("events and predictions must have equal length")
    by_story: dict[str, list[tuple[Any, str, float | None]]] = defaultdict(list)
    for index, (event, action) in enumerate(zip(events, actions)):
        truth = truth_by_event[event.event_id]
        score = scores[index] if scores is not None else None
        by_story[str(truth["story_id"])].append((event, action, score))
    positive_stories = {
        story_id for story_id, rows in by_story.items()
        if any(truth_by_event[event.event_id]["label"] == 1 for event, _action, _score in rows)
    }
    detected: set[str] = set()
    leads: list[float] = []
    for story_id, rows in by_story.items():
        alerts = []
        for event, action, score in rows:
            selected = action in ("STEP_UP", "ANALYST_REVIEW")
            if b0_threshold is not None and score is not None:
                selected = selected or score >= b0_threshold
            if selected:
                alerts.append(event.occurred_at)
        if story_id in positive_stories and alerts:
            detected.add(story_id)
            final_time = max(event.occurred_at for event, _action, _score in rows)
            leads.append(max(0.0, (final_time - min(alerts)).total_seconds() / 60.0))
    undetected = positive_stories - detected
    return {
        "positive_story_count": len(positive_stories),
        "detected_story_count": len(detected),
        "undetected_positive_story_count": len(undetected),
        "story_recall": round(len(detected) / len(positive_stories), 4) if positive_stories else None,
        "mean_lead_time_minutes": round(mean(leads), 4) if leads else None,
        "lead_time_denominator_detected_stories": len(leads),
        "lead_time_status": "conditional_on_detected_positive_stories",
    }


def duplicate_alert_ratio_by_story(events: Sequence[Any], truth_by_event: Mapping[str, Mapping[str, Any]], actions: Sequence[str]) -> float:
    alerted = [str(truth_by_event[event.event_id]["story_id"]) for event, action in zip(events, actions) if action in ("STEP_UP", "ANALYST_REVIEW")]
    return round(1.0 - len(set(alerted)) / len(alerted), 4) if alerted else 0.0


def innocent_friction_unknown(labels: Sequence[int], actions: Sequence[str]) -> dict[str, Any]:
    if len(labels) != len(actions):
        raise ValueError("labels and actions must have equal length")
    legitimate = [(label, action) for label, action in zip(labels, actions) if label == 0]
    unknown = sum(1 for label, action in legitimate if action == "UNKNOWN")
    scored = [(label, action) for label, action in legitimate if action != "UNKNOWN"]
    friction = sum(action in ("WARN_AND_VERIFY", "STEP_UP", "ANALYST_REVIEW") for _label, action in scored)
    review = sum(action in ("STEP_UP", "ANALYST_REVIEW") for _label, action in scored)
    n = len(legitimate)
    return {
        "n": n,
        "scored_n": len(scored),
        "unknown_n": unknown,
        "false_friction_rate": round(friction / n, 4) if n else 0.0,
        "innocent_review_rate": round(review / n, 4) if n else 0.0,
    }


def story_bootstrap_interval(
    story_rows: Mapping[str, Sequence[int]],
    *,
    metric: Callable[[list[int]], float | None],
    seed: int = 7,
    replicates: int = 200,
) -> dict[str, Any]:
    """Bootstrap complete story units; no event is sampled independently."""
    story_ids = sorted(story_rows)
    if not story_ids or replicates <= 0:
        return {"value": None, "low": None, "high": None, "replicates": 0, "ci_status": "no_stories"}
    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(replicates):
        sampled = [rng.choice(story_ids) for _ in story_ids]
        rows = [value for story_id in sampled for value in story_rows[story_id]]
        value = metric(rows)
        if value is not None:
            values.append(float(value))
    observed = metric([value for story_id in story_ids for value in story_rows[story_id]])
    return {
        "value": round(float(observed), 4) if observed is not None else None,
        "low": percentile(values, 2.5),
        "high": percentile(values, 97.5),
        "replicates": replicates,
        "bootstrap_seed": seed,
        "unit": "complete_story",
        "ci_status": "descriptive" if values else "no_supported_replicates",
    }


def aggregate_seed_values(values_by_seed: Mapping[int, float | None]) -> dict[str, Any]:
    values = [float(value) for value in values_by_seed.values() if value is not None]
    return {
        "per_seed": {str(seed): value for seed, value in sorted(values_by_seed.items())},
        "seed_n": len(values_by_seed),
        "scored_seed_n": len(values),
        "mean": round(mean(values), 4) if values else None,
        "interval": {"low": percentile(values, 2.5), "high": percentile(values, 97.5)} if values else None,
        "status": "descriptive_multi_seed" if values else "no_values",
    }


__all__ = [
    "aggregate_seed_values",
    "brier_unknown",
    "budget_metrics",
    "coverage_metrics",
    "duplicate_alert_ratio_by_story",
    "ece_unknown",
    "grouped_error_unknown",
    "innocent_friction_unknown",
    "macro_f1_unknown",
    "pr_auc_unknown",
    "precision_recall_at_budget_v2",
    "story_bootstrap_interval",
    "story_detection_metrics",
]
