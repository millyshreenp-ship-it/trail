"""Deterministic synthetic evaluation for EarlyTrace.

Writes manifest.json, metrics.json, and a reliability SVG.
Does not download external datasets and does not train a neural model.
"""
from __future__ import annotations

import argparse
import json
import time
import tracemalloc
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from app.config import VERSION
from app.evaluation.v1_motifs import build_event_index, extract_motif_features, motif_vector
from app.evaluation.v1_compat import ENGINE_VERSION, FEATURE_CONTRACT, PreAuthContext, _b0_score, events_to_transactions, score_pre_auth
from app.evaluation.metrics import (
    brier,
    duplicate_alert_ratio,
    expected_calibration_error,
    grouped_error,
    innocent_friction,
    macro_f1,
    percentile,
    pr_auc,
    precision_recall_at_budget,
    risk_coverage,
)
from app.evaluation.splits import inductive_holdout, legitimate_stress, open_set_split, temporal_masks
from app.simulator.generator import generate_preauth_corpus, write_manifest

ALERTS_PER_THOUSAND = 20.0
ROOT = Path(__file__).resolve().parents[3]


def _past(events, index: int):
    event = events[index]
    return [e for e in events[: index + 1] if e.occurred_at <= event.occurred_at]


def score_b1(events, *, hub_available: bool = True, participating: list[str] | None = None, expected: int = 1):
    actions, scores, vectors = [], [], []
    for i, event in enumerate(events):
        past = _past(events, i)
        ctx = PreAuthContext(
            events=past,
            as_of=event.occurred_at,
            hub_available=hub_available,
            participating_institutions=participating,
            expected_institutions=expected,
        )
        decision = score_pre_auth(event, ctx, optional_beacons=None)
        actions.append(decision.action.value)
        scores.append(decision.score)
        index = build_event_index(past, event.occurred_at)
        vectors.append(motif_vector(extract_motif_features(index, event.payee_token, event.occurred_at)))
    return actions, scores, vectors


def score_b0(events) -> list[float]:
    scores = []
    for i, event in enumerate(events):
        past = _past(events, i)
        txs = events_to_transactions(past)
        vals = [v for v in (
            _b0_score(txs, event.payee_token, event.occurred_at),
            _b0_score(txs, event.source_token, event.occurred_at),
        ) if v is not None]
        scores.append(max(vals) if vals else 0.0)
    return scores


def _labels_for(events, labels):
    return [int(labels[e.event_id]["label"]) for e in events]


def _lead_minutes(events, labels, alerted: list[bool]) -> float | None:
    by_story: dict[str, list] = defaultdict(list)
    for e, flag in zip(events, alerted):
        meta = labels[e.event_id]
        if meta["label"] != 1:
            continue
        by_story[meta["story_id"]].append((e, flag))
    leads = []
    for rows in by_story.values():
        final = max(e.occurred_at for e, _ in rows)
        alerts = [e.occurred_at for e, flag in rows if flag]
        if not alerts:
            continue
        first = min(alerts)
        leads.append(max(0.0, (final - first).total_seconds() / 60.0))
    if not leads:
        return None
    return round(sum(leads) / len(leads), 3)


def _try_hgb(train_x, train_y, cal_x, cal_y, test_x):
    try:
        from sklearn.ensemble import HistGradientBoostingClassifier
        from sklearn.linear_model import LogisticRegression
    except ImportError:
        return {"available": False, "reason": "scikit-learn is not installed"}
    if len(set(train_y)) < 2 or len(train_y) < 10:
        return {"available": False, "reason": "training split does not contain both classes"}
    clf = HistGradientBoostingClassifier(
        max_depth=3, max_iter=40, learning_rate=0.1, random_state=0,
    )
    clf.fit(train_x, train_y)
    raw_test = clf.predict_proba(test_x)[:, 1]
    calibrated = False
    version = "HistGradientBoostingClassifier-max_depth-3-max_iter-40"
    scores = raw_test
    if len(cal_y) >= 8 and len(set(cal_y)) >= 2:
        cal_raw = clf.predict_proba(cal_x)[:, 1].reshape(-1, 1)
        platt = LogisticRegression(random_state=0)
        platt.fit(cal_raw, cal_y)
        scores = platt.predict_proba(raw_test.reshape(-1, 1))[:, 1]
        calibrated = True
        version += "+platt-on-time-separated-calibration"
    return {
        "available": True,
        "calibrated": calibrated,
        "version": version,
        "scores": [round(float(s), 4) for s in scores],
        "feature_contract": FEATURE_CONTRACT,
    }


def _reliability_svg(curve: list[dict]) -> str:
    width, height = 320, 220
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        '<rect width="100%" height="100%" fill="#0f1420"/>',
        '<line x1="40" y1="20" x2="40" y2="180" stroke="#8a96b0"/>',
        '<line x1="40" y1="180" x2="300" y2="180" stroke="#8a96b0"/>',
        '<line x1="40" y1="180" x2="300" y2="20" stroke="#26304a"/>',
        '<text x="48" y="16" fill="#e6ebf5" font-size="12">Reliability (synthetic, uncalibrated unless noted)</text>',
    ]
    if curve:
        pts = []
        for row in curve:
            x = 40 + row["confidence"] * 260
            y = 180 - row["accuracy"] * 160
            pts.append(f"{x:.1f},{y:.1f}")
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="#5b8cff"/>')
        if len(pts) >= 2:
            parts.append(f'<polyline fill="none" stroke="#5b8cff" points="{" ".join(pts)}"/>')
    parts.append("</svg>")
    return "\n".join(parts)


def _latency_sample(event, past) -> dict:
    samples = {k: [] for k in ("features_ms", "index_ms", "score_ms", "serialize_ms", "e2e_ms")}
    for _ in range(30):
        t0 = time.perf_counter()
        index = build_event_index(past, event.occurred_at)
        t1 = time.perf_counter()
        extract_motif_features(index, event.payee_token, event.occurred_at)
        t2 = time.perf_counter()
        decision = score_pre_auth(event, PreAuthContext(events=past, as_of=event.occurred_at), None)
        t3 = time.perf_counter()
        decision.model_dump(mode="json")
        t4 = time.perf_counter()
        samples["index_ms"].append((t1 - t0) * 1000)
        samples["features_ms"].append((t2 - t1) * 1000)
        samples["score_ms"].append((t3 - t2) * 1000)
        samples["serialize_ms"].append((t4 - t3) * 1000)
        samples["e2e_ms"].append((t4 - t0) * 1000)
    return {
        name: {"p50": percentile(vals, 50), "p95": percentile(vals, 95), "p99": percentile(vals, 99)}
        for name, vals in samples.items()
    }


def run_evaluation(*, seed: int = 7, n_days: int = 24, out_dir: Path | None = None) -> dict:
    corpus = generate_preauth_corpus(seed=seed, n_days=n_days, stories_per_day=1)
    events = corpus["events"]
    labels = corpus["labels"]
    manifest = dict(corpus["manifest"])
    manifest.update({
        "model_config_version": ENGINE_VERSION,
        "feature_contract": FEATURE_CONTRACT,
        "code_version": VERSION,
        "data_status": "synthetic",
        "alerts_per_thousand": ALERTS_PER_THOUSAND,
        "neural_model_trained": False,
        "external_datasets": [],
    })
    bounds = manifest["split_boundaries"]
    train_end = datetime.fromisoformat(bounds["train_end"])
    cal_end = datetime.fromisoformat(bounds["calibration_end"])
    parts = temporal_masks(events, train_end, cal_end)

    tracemalloc.start()
    t_score = time.perf_counter()
    actions, b1_scores, vectors = score_b1(events)
    b0_scores = score_b0(events)
    elapsed = time.perf_counter() - t_score
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    by_id = {e.event_id: i for i, e in enumerate(events)}
    y = _labels_for(events, labels)
    pred = [1 if a in ("STEP_UP", "ANALYST_REVIEW") else 0 for a in actions]
    scenarios = [labels[e.event_id]["scenario"] for e in events]
    institutions = [e.institution_id for e in events]
    stories = [labels[e.event_id]["story_id"] for e in events]
    alerted = [p == 1 for p in pred]

    def _subset_metric(subset):
        idx = [by_id[e.event_id] for e in subset]
        ys = [y[i] for i in idx]
        return {
            "n": len(idx),
            "b0_budget": precision_recall_at_budget([b0_scores[i] for i in idx], ys, alerts_per_thousand=ALERTS_PER_THOUSAND),
            "b1_budget": precision_recall_at_budget(
                [b1_scores[i] if b1_scores[i] is not None else -1 for i in idx], ys, alerts_per_thousand=ALERTS_PER_THOUSAND,
            ),
            "b1_pr_auc": pr_auc([b1_scores[i] or 0.0 for i in idx], ys),
            "b0_pr_auc": pr_auc([b0_scores[i] for i in idx], ys),
        }

    test_events = parts["test"]
    test_idx = [by_id[e.event_id] for e in test_events]
    test_y = [y[i] for i in test_idx]
    test_b1 = [b1_scores[i] if b1_scores[i] is not None else -1.0 for i in test_idx]
    test_b0 = [b0_scores[i] for i in test_idx]
    b0_budget = precision_recall_at_budget(test_b0, test_y, alerts_per_thousand=ALERTS_PER_THOUSAND)
    b1_budget = precision_recall_at_budget(test_b1, test_y, alerts_per_thousand=ALERTS_PER_THOUSAND)
    b0_lead = _lead_minutes(events, labels, [s >= 0.60 for s in b0_scores])
    b1_lead = _lead_minutes(events, labels, alerted)

    hgb = _try_hgb(
        [vectors[by_id[e.event_id]] for e in parts["train"]],
        [y[by_id[e.event_id]] for e in parts["train"]],
        [vectors[by_id[e.event_id]] for e in parts["calibration"]],
        [y[by_id[e.event_id]] for e in parts["calibration"]],
        [vectors[by_id[e.event_id]] for e in parts["test"]],
    )
    hgb_budget = None
    if hgb.get("available") and hgb.get("scores"):
        hgb_budget = precision_recall_at_budget(hgb["scores"], test_y, alerts_per_thousand=ALERTS_PER_THOUSAND)

    b1_prec = b1_budget["precision"]
    b0_prec = b0_budget["precision"]
    winner = "b0_heuristic" if b0_prec > b1_prec else "b1_motif_policy"
    if b1_lead is not None and b0_lead is not None and b1_prec == b0_prec and b1_lead > b0_lead:
        winner = "b1_motif_policy"
    hgb_note = "not selected"
    if hgb_budget and hgb_budget["precision"] > max(b0_prec, b1_prec):
        hgb_note = "higher alert-budget precision on this synthetic temporal test; not loaded into the API"
        winner = "b1_hgb_offline"
    elif hgb_budget:
        hgb_note = "did not beat the stronger of B0 and B1 on alert-budget precision"

    # Partial participation: hide every institution except the event's own by scoring BANK_A-only stream.
    bank_a = [e for e in events if e.institution_id == "BANK_A"]
    partial_actions, partial_scores, _ = score_b1(bank_a, participating=["BANK_A"], expected=3)
    partial_y = _labels_for(bank_a, labels)
    partial_pred = [1 if a in ("STEP_UP", "ANALYST_REVIEW") else 0 for a in partial_actions]

    ind_train, ind_test = inductive_holdout(events)
    open_train, open_test = open_set_split(events, labels, held_out_scenario="split_value")
    stress = legitimate_stress(events, labels)
    stress_idx = [by_id[e.event_id] for e in stress]
    stress_actions = [actions[i] for i in stress_idx]
    stress_y = [y[i] for i in stress_idx]

    cal_curve = expected_calibration_error(
        [b1_scores[i] or 0.0 for i in test_idx], test_y,
    )
    run_id = f"synthetic-seed{seed}-d{n_days}"
    dest = out_dir or (ROOT / "data" / "evaluation" / run_id)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "plots").mkdir(exist_ok=True)
    (dest / "plots" / "reliability.svg").write_text(_reliability_svg(cal_curve["reliability"]), encoding="utf-8")

    latency = _latency_sample(events[len(events) // 2], _past(events, len(events) // 2)) if events else {}
    metrics = {
        "data_status": "synthetic",
        "seed": seed,
        "split": "temporal",
        "split_boundaries": bounds,
        "engine_version": ENGINE_VERSION,
        "feature_contract": FEATURE_CONTRACT,
        "code_version": VERSION,
        "neural_model_trained": False,
        "calibrated_runtime": False,
        "conformal_used": False,
        "conformal_reason": "Time-ordered payments are not exchangeable, so split-conformal coverage is not claimed.",
        "n_events": len(events),
        "temporal_test": {
            "n": len(test_events),
            "b0": b0_budget,
            "b1": b1_budget,
            "b0_pr_auc": pr_auc(test_b0, test_y),
            "b1_pr_auc": pr_auc([0.0 if s < 0 else s for s in test_b1], test_y),
            "b0_brier_uncalibrated": brier(test_b0, test_y),
            "b1_brier_uncalibrated": brier([None if s < 0 else s for s in test_b1], test_y),
            "b1_ece_uncalibrated": cal_curve,
        },
        "lead_time_minutes_mean": {"b0_score_at_least_0.60": b0_lead, "b1_step_up_or_review": b1_lead},
        "full_stream_policy": {
            "macro_f1": macro_f1(pred, y),
            "by_scenario": grouped_error(pred, y, scenarios),
            "by_institution": grouped_error(pred, y, institutions),
            "risk_coverage": risk_coverage(b1_scores, y, actions),
            "duplicate_alert_ratio": duplicate_alert_ratio(stories, alerted),
            "innocent_friction": innocent_friction(y, actions),
        },
        "splits": {
            "temporal_counts": {k: len(v) for k, v in parts.items()},
            "inductive_counts": {"train": len(ind_train), "test": len(ind_test)},
            "inductive_test": _subset_metric(ind_test),
            "open_set_counts": {"train": len(open_train), "test": len(open_test)},
            "open_set_split_value_test": _subset_metric(open_test),
            "open_set_train_excludes": "split_value",
            "legitimate_stress": {
                "n": len(stress),
                "innocent_friction": innocent_friction(stress_y, stress_actions),
            },
            "partial_participation_bank_a_only": {
                "n": len(bank_a),
                "budget": precision_recall_at_budget(
                    [s if s is not None else -1 for s in partial_scores], partial_y,
                    alerts_per_thousand=ALERTS_PER_THOUSAND,
                ),
                "policy_recall": round(sum(p and yy for p, yy in zip(partial_pred, partial_y)) / sum(partial_y), 4) if sum(partial_y) else None,
            },
        },
        "classical_model": {
            "estimator": hgb.get("version"),
            "available": hgb.get("available"),
            "reason": hgb.get("reason"),
            "calibrated_on": "time-separated calibration window" if hgb.get("calibrated") else None,
            "temporal_test_budget": hgb_budget,
            "selection_note": hgb_note,
        },
        "comparison": {
            "predeclared_metric": "precision at 20 alerts per 1,000 temporal-test events",
            "b0_precision": b0_prec,
            "b1_precision": b1_prec,
            "offline_winner": winner,
            "runtime_engine": ENGINE_VERSION,
            "runtime_note": "The API serves the feature-linked B0/B1 policy. A classical model is an offline comparison on this synthetic corpus.",
        },
        "latency_ms": latency,
        "resources": {
            "score_wall_seconds": round(elapsed, 4),
            "throughput_events_per_second": round(len(events) / elapsed, 3) if elapsed else None,
            "tracemalloc_peak_bytes": peak,
        },
        "attack_degradation": _degradation(events, labels),
        "known_limit": "Metrics describe this synthetic generator only.",
    }
    manifest["offline_winner"] = winner
    write_manifest(dest / "manifest.json", manifest)
    (dest / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return {"run_id": run_id, "path": str(dest), "metrics": metrics, "manifest": manifest}


def _degradation(events, labels) -> dict:
    """Compare policy recall before and after shifting planted mule forwards later."""
    from datetime import timedelta

    base_actions, _, _ = score_b1(events)
    shifted = []
    for e in events:
        if labels[e.event_id]["role"] == "mule_forward":
            shifted.append(e.model_copy(update={
                "occurred_at": e.occurred_at + timedelta(hours=30),
                "as_of": e.as_of + timedelta(hours=30),
            }))
        else:
            shifted.append(e)
    shifted = sorted(shifted, key=lambda e: (e.occurred_at, e.event_id))
    new_actions, _, _ = score_b1(shifted)
    y = _labels_for(events, labels)
    y2 = _labels_for(shifted, labels)
    base_hit = sum(1 for a, yy in zip(base_actions, y) if yy == 1 and a in ("STEP_UP", "ANALYST_REVIEW"))
    new_hit = sum(1 for a, yy in zip(new_actions, y2) if yy == 1 and a in ("STEP_UP", "ANALYST_REVIEW"))
    pos = sum(y) or 1
    return {
        "name": "mule_forward_shifted_30h",
        "recall_before": round(base_hit / pos, 4),
        "recall_after": round(new_hit / sum(y2 or [1]), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic EarlyTrace evaluation")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--days", type=int, default=24)
    parser.add_argument("--out", type=str, default="")
    args = parser.parse_args()
    result = run_evaluation(seed=args.seed, n_days=args.days, out_dir=Path(args.out) if args.out else None)
    metrics = result["metrics"]
    print(json.dumps({
        "data_status": "synthetic",
        "split": metrics["split"],
        "seed": metrics["seed"],
        "engine_version": metrics["engine_version"],
        "path": result["path"],
        "offline_winner": metrics["comparison"]["offline_winner"],
        "b0_precision": metrics["comparison"]["b0_precision"],
        "b1_precision": metrics["comparison"]["b1_precision"],
    }, indent=2))


if __name__ == "__main__":
    main()
