"""Evaluation metrics for synthetic EarlyTrace runs.

Scores are not treated as calibrated probabilities unless the caller sets
calibrated=True after a time-separated calibration fit.
"""
from __future__ import annotations

from collections import defaultdict


def _trap(xs: list[float], ys: list[float]) -> float:
    if len(xs) < 2:
        return 0.0
    area = 0.0
    for i in range(1, len(xs)):
        area += (xs[i] - xs[i - 1]) * (ys[i] + ys[i - 1]) / 2.0
    return area


def pr_auc(scores: list[float], labels: list[int]) -> float | None:
    pairs = [(s, y) for s, y in zip(scores, labels) if s is not None and y is not None]
    if not pairs or sum(y for _, y in pairs) == 0:
        return None
    pairs.sort(key=lambda p: p[0], reverse=True)
    tp = 0
    fp = 0
    pos = sum(y for _, y in pairs)
    neg = len(pairs) - pos
    curve = [(0.0, 1.0)]
    for s, y in pairs:
        if y == 1:
            tp += 1
        else:
            fp += 1
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / pos if pos else 0.0
        curve.append((rec, prec))
    curve.sort()
    return round(_trap([c[0] for c in curve], [c[1] for c in curve]), 4)


def precision_recall_at_budget(scores: list[float], labels: list[int], *, alerts_per_thousand: float) -> dict:
    ranked = sorted(
        [(s if s is not None else -1.0, y, i) for i, (s, y) in enumerate(zip(scores, labels))],
        key=lambda row: row[0],
        reverse=True,
    )
    n = len(ranked)
    k = max(1, int(round(n * alerts_per_thousand / 1000.0))) if n else 0
    chosen = [row for row in ranked[:k] if row[0] >= 0]
    tp = sum(1 for s, y, _i in chosen if y == 1)
    fp = sum(1 for s, y, _i in chosen if y == 0)
    pos = sum(1 for y in labels if y == 1)
    return {
        "alerts_per_thousand": alerts_per_thousand,
        "alert_count": len(chosen),
        "precision": round(tp / len(chosen), 4) if chosen else 0.0,
        "recall": round(tp / pos, 4) if pos else 0.0,
    }


def recall_at_capacity(actions: list[str], labels: list[int], *, capacity: int) -> float | None:
    flagged = [y for action, y in zip(actions, labels) if action in ("STEP_UP", "ANALYST_REVIEW")]
    if capacity <= 0:
        return None
    flagged = flagged[:capacity]
    pos = sum(labels)
    if not pos:
        return None
    return round(sum(flagged) / pos, 4)


def binary_counts(pred: list[int], labels: list[int]) -> dict:
    tp = sum(1 for p, y in zip(pred, labels) if p == 1 and y == 1)
    fp = sum(1 for p, y in zip(pred, labels) if p == 1 and y == 0)
    fn = sum(1 for p, y in zip(pred, labels) if p == 0 and y == 1)
    tn = sum(1 for p, y in zip(pred, labels) if p == 0 and y == 0)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "fpr": round(fpr, 4), "fnr": round(fnr, 4), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def macro_f1(pred: list[int], labels: list[int]) -> float | None:
    if not labels:
        return None
    pos = binary_counts(pred, labels)["f1"]
    inv_p = [1 - p for p in pred]
    inv_y = [1 - y for y in labels]
    neg = binary_counts(inv_p, inv_y)["f1"]
    return round((pos + neg) / 2.0, 4)


def brier(scores: list[float], labels: list[int]) -> float | None:
    pairs = [(s, y) for s, y in zip(scores, labels) if s is not None]
    if not pairs:
        return None
    return round(sum((s - y) ** 2 for s, y in pairs) / len(pairs), 4)


def expected_calibration_error(scores: list[float], labels: list[int], *, bins: int = 10) -> dict:
    pairs = [(s, y) for s, y in zip(scores, labels) if s is not None]
    if not pairs:
        return {"ece": None, "reliability": []}
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(bins)]
    for s, y in pairs:
        idx = min(bins - 1, int(s * bins))
        buckets[idx].append((s, y))
    ece = 0.0
    curve = []
    for i, bucket in enumerate(buckets):
        if not bucket:
            continue
        conf = sum(s for s, _ in bucket) / len(bucket)
        acc = sum(y for _, y in bucket) / len(bucket)
        ece += (len(bucket) / len(pairs)) * abs(acc - conf)
        curve.append({"bin": i, "count": len(bucket), "confidence": round(conf, 4), "accuracy": round(acc, 4)})
    return {"ece": round(ece, 4), "reliability": curve}


def risk_coverage(scores: list[float | None], labels: list[int], actions: list[str]) -> dict:
    decided = [(s, y) for s, y, a in zip(scores, labels, actions) if a != "UNKNOWN" and s is not None]
    unknown = sum(1 for a in actions if a == "UNKNOWN")
    if not decided:
        return {"unknown_rate": 1.0 if actions else 0.0, "selective_risk": None, "coverage": 0.0}
    # Risk among non-abstentions: error of a 0.5 threshold on the uncalibrated score.
    errors = sum(1 for s, y in decided if (s >= 0.5) != bool(y))
    return {
        "unknown_rate": round(unknown / len(actions), 4) if actions else 0.0,
        "coverage": round(len(decided) / len(actions), 4) if actions else 0.0,
        "selective_risk": round(errors / len(decided), 4),
    }


def grouped_error(pred: list[int], labels: list[int], groups: list[str]) -> dict:
    by: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for p, y, g in zip(pred, labels, groups):
        by[g].append((p, y))
    out = {}
    for g, rows in sorted(by.items()):
        ps = [p for p, _ in rows]
        ys = [y for _, y in rows]
        counts = binary_counts(ps, ys)
        out[g] = {"fpr": counts["fpr"], "fnr": counts["fnr"], "n": len(rows)}
    return out


def duplicate_alert_ratio(story_ids: list[str], alerted: list[bool]) -> float:
    stories = [s for s, a in zip(story_ids, alerted) if a]
    if not stories:
        return 0.0
    return round(1.0 - (len(set(stories)) / len(stories)), 4)


def innocent_friction(labels: list[int], actions: list[str]) -> dict:
    innocent = [(y, a) for y, a in zip(labels, actions) if y == 0]
    if not innocent:
        return {"false_friction_rate": 0.0, "innocent_review_rate": 0.0, "n": 0}
    friction = sum(1 for _y, a in innocent if a in ("WARN_AND_VERIFY", "STEP_UP", "ANALYST_REVIEW"))
    review = sum(1 for _y, a in innocent if a in ("STEP_UP", "ANALYST_REVIEW"))
    n = len(innocent)
    return {
        "false_friction_rate": round(friction / n, 4),
        "innocent_review_rate": round(review / n, 4),
        "n": n,
    }


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
    return round(ordered[idx], 4)


# The v1 helpers above remain unchanged. These lazy wrappers expose the
# corrected UNKNOWN-aware surface without introducing an import cycle or
# changing the frozen --days evaluator.
def budget_metrics(*args, **kwargs):
    from app.evaluation.metrics_v2 import budget_metrics as implementation
    return implementation(*args, **kwargs)


def pr_auc_unknown(*args, **kwargs):
    from app.evaluation.metrics_v2 import pr_auc_unknown as implementation
    return implementation(*args, **kwargs)


def precision_recall_at_budget_v2(*args, **kwargs):
    from app.evaluation.metrics_v2 import budget_metrics as implementation
    return implementation(*args, **kwargs)


def brier_unknown(*args, **kwargs):
    from app.evaluation.metrics_v2 import brier_unknown as implementation
    return implementation(*args, **kwargs)


def ece_unknown(*args, **kwargs):
    from app.evaluation.metrics_v2 import ece_unknown as implementation
    return implementation(*args, **kwargs)


def grouped_error_unknown(*args, **kwargs):
    from app.evaluation.metrics_v2 import grouped_error_unknown as implementation
    return implementation(*args, **kwargs)


def macro_f1_unknown(*args, **kwargs):
    from app.evaluation.metrics_v2 import macro_f1_unknown as implementation
    return implementation(*args, **kwargs)


def coverage_metrics(*args, **kwargs):
    from app.evaluation.metrics_v2 import coverage_metrics as implementation
    return implementation(*args, **kwargs)


def story_detection_metrics(*args, **kwargs):
    from app.evaluation.metrics_v2 import story_detection_metrics as implementation
    return implementation(*args, **kwargs)


def story_bootstrap_interval(*args, **kwargs):
    from app.evaluation.metrics_v2 import story_bootstrap_interval as implementation
    return implementation(*args, **kwargs)


def aggregate_seed_values(*args, **kwargs):
    from app.evaluation.metrics_v2 import aggregate_seed_values as implementation
    return implementation(*args, **kwargs)


def duplicate_alert_ratio_by_story(*args, **kwargs):
    from app.evaluation.metrics_v2 import duplicate_alert_ratio_by_story as implementation
    return implementation(*args, **kwargs)


def innocent_friction_unknown(*args, **kwargs):
    from app.evaluation.metrics_v2 import innocent_friction_unknown as implementation
    return implementation(*args, **kwargs)
