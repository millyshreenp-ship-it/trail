"""Corrected complete-story sim-2 research evaluator.

This module is separate from the frozen v1 ``--days`` evaluator.  It joins
planted truth only after detector scoring and reports abstentions honestly.
"""
from __future__ import annotations

import csv
import json
import time
import tracemalloc
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from app.config import VERSION
from app.context.preauth import (
    ConsentResult,
    ContextFailure,
    CurrentEventRecord,
    ParticipationResult,
)
from app.detection.preauth import score_pre_auth_v2
from app.detection.features_contract import feature_vector_for_event
from app.evaluation.adversarial import adversarial_inventory, evaluate_policy_degradation
from app.evaluation.metrics_v2 import (
    aggregate_seed_values,
    brier_unknown,
    budget_metrics,
    coverage_metrics,
    duplicate_alert_ratio_by_story,
    ece_unknown,
    grouped_error_unknown,
    innocent_friction_unknown,
    macro_f1_unknown,
    pr_auc_unknown,
    story_bootstrap_interval,
    story_detection_metrics,
)
from app.evaluation.splits import StorySplit, split_complete_stories
from app.evaluation.truth import truth_checksum, validate_truth_by_event
from app.models.preauth import ConsentOutcome, Participation, PreAuthEventV2
from app.research.baselines import B0Baseline, B1Baseline, HGBBaseline
from app.research.manifests import (
    build_candidate_manifest,
    dependency_lock_hash,
    resolved_library_versions,
    sha256_file,
    sha256_json,
    write_candidate_manifest,
)
from app.simulator.sim2 import CorpusConfig, SIM2_VERSION, generate_sim2_corpus

ALERTS_PER_THOUSAND = 20.0
RESEARCH_ENGINE = "earlytrace-b0b1-heuristic-v2"
ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class ResearchContext:
    """Detector-safe context assembled from events, never from planted truth."""

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
    visible_institutions: frozenset[str] | None = None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("evaluation timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _history(events: Sequence[PreAuthEventV2], current: PreAuthEventV2) -> tuple[PreAuthEventV2, ...]:
    return tuple(
        event for event in events
        if event.event_id != current.event_id and _utc(event.occurred_at) < _utc(current.occurred_at)
    )


def _context_for(event: PreAuthEventV2, events: Sequence[PreAuthEventV2], *, hub_available: bool = True, visible_institutions: set[str] | None = None, expected_institutions: frozenset[str] | None = None) -> ResearchContext:
    prior = _history(events, event)
    expected = expected_institutions if expected_institutions is not None else frozenset(item.institution_id for item in events)
    cross_consent = event.consent_scope.value == "CONSENTED_BEACON"
    if visible_institutions is None:
        visible = expected if cross_consent else frozenset({event.institution_id})
    else:
        visible = frozenset(visible_institutions)
        if not cross_consent:
            visible &= {event.institution_id}
    if not hub_available and cross_consent:
        visible = frozenset()
    visible_prior = tuple(item for item in prior if item.institution_id in visible)
    same_payee = {item.event_id for item in visible_prior if item.payee_token == event.payee_token}
    known_age = event.payee_age_bucket.value != "unknown"
    if cross_consent:
        granting = next((institution for institution in expected if institution != event.institution_id), event.institution_id)
        consent = ConsentResult(ConsentOutcome.VERIFIED_CROSS_INSTITUTION, True, granting, event.institution_id)
    else:
        consent = ConsentResult(ConsentOutcome.VERIFIED_LOCAL, True, event.institution_id, event.institution_id)
    if not hub_available and cross_consent:
        participation = Participation.NONE
        failure = ContextFailure.UNAVAILABLE
        coverage = 0.0
    elif not hub_available:
        participation = Participation.LOCAL_ONLY
        failure = ContextFailure.NONE
        coverage = 1.0
    elif visible == expected:
        participation = Participation.FULL
        failure = ContextFailure.NONE
        coverage = 1.0
    else:
        participation = Participation.PARTIAL
        failure = ContextFailure.NONE
        coverage = 0.75
    return ResearchContext(
        current_event=CurrentEventRecord(event, attestation_verified=True, local_authorized=True),
        events=visible_prior,
        consent=consent,
        participation=ParticipationResult(participation, participation == Participation.LOCAL_ONLY),
        expected_institutions=expected,
        hub_available=hub_available,
        evidence_coverage=coverage,
        qualifying_prior_count=len(same_payee),
        local_sufficient=(failure == ContextFailure.NONE and (known_age or len(same_payee) >= 2)),
        context_snapshot_id="research-context",
        failure_code=failure,
        visible_institutions=visible,
    )


def _contexts_for(events: Sequence[PreAuthEventV2], **kwargs) -> list[ResearchContext]:
    expected = frozenset(event.institution_id for event in events)
    accounts: dict[str, dict[str, PreAuthEventV2]] = defaultdict(dict)
    for event in events:
        accounts[event.source_token][event.event_id] = event
        accounts[event.payee_token][event.event_id] = event
    contexts = []
    for event in events:
        relevant = {**accounts[event.source_token], **accounts[event.payee_token]}
        contexts.append(_context_for(event, tuple(relevant.values()), expected_institutions=expected, **kwargs))
    return contexts


def _split_events(split: StorySplit) -> list[PreAuthEventV2]:
    return list(split.events)


def _event_keys(events: Sequence[PreAuthEventV2]) -> list[tuple[str, str]]:
    return [(_utc(event.occurred_at).isoformat(), event.event_id) for event in events]


def _labels(events: Sequence[PreAuthEventV2], truth_by_event: Mapping[str, Mapping[str, Any]]) -> list[int]:
    return [int(truth_by_event[event.event_id]["label"]) for event in events]


def _policy_predictions(actions: Sequence[str]) -> list[int | None]:
    return [None if action == "UNKNOWN" else int(action in ("STEP_UP", "ANALYST_REVIEW")) for action in actions]


def _capacity_recall(scores: Sequence[float | None], labels: Sequence[int], capacity: int) -> dict[str, Any]:
    positives = sum(labels)
    ranked = sorted(
        [(float(score), int(label), index) for index, (score, label) in enumerate(zip(scores, labels)) if score is not None],
        key=lambda row: (-row[0], row[2]),
    )
    selected = ranked[: max(0, capacity)]
    hit = sum(label for _score, label, _index in selected)
    return {
        "capacity": capacity,
        "eligible_n": len(labels),
        "scored_n": len(ranked),
        "unknown_n": len(labels) - len(ranked),
        "selected_alerts": len(selected),
        "recall": round(hit / positives, 4) if positives else 0.0,
    }


def _actions_for_stream(events: Sequence[PreAuthEventV2]) -> list[str]:
    contexts = _contexts_for(events)
    return [
        score_pre_auth_v2(event, context, server_now=event.occurred_at).action.value
        for event, context in zip(events, contexts)
    ]


def _measure_prediction(baseline, events, contexts):
    tracemalloc.start()
    started = time.perf_counter()
    try:
        scores = baseline.predict(events, contexts)
        elapsed = time.perf_counter() - started
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    samples = []
    if events and any(score is not None for score in scores):
        sample_index = next(index for index, score in enumerate(scores) if score is not None)
        for _ in range(30):
            started = time.perf_counter()
            baseline.predict([events[sample_index]], [contexts[sample_index]])
            samples.append((time.perf_counter() - started) * 1000)
    return scores, {
        "prediction_seconds": round(elapsed, 6),
        "throughput_events_per_second": round(len(events) / elapsed, 3) if elapsed else None,
        "tracemalloc_peak_bytes": peak,
        "single_event_latency_ms": _percentiles(samples),
        "measurement": "unloaded in-process; Python allocations, not process RSS or service SLO",
    }


def _candidate_report(events, truth, scores, actions, *, threshold, resources, status):
    labels = _labels(events, truth)
    positive_stories = {truth[event.event_id]["story_id"] for event in events if truth[event.event_id]["label"] == 1}
    predictions = _policy_predictions(actions)
    story_report = story_detection_metrics(events, truth, actions, scores=scores)
    flags = {
        str(story_id): [int(any(action in ("STEP_UP", "ANALYST_REVIEW") for event, action in zip(events, actions) if truth[event.event_id]["story_id"] == story_id))]
        for story_id in positive_stories
    }
    story_report["story_bootstrap_interval"] = story_bootstrap_interval(
        flags, metric=lambda values: sum(values) / len(values) if values else None,
    )
    flagged = [action in ("STEP_UP", "ANALYST_REVIEW") for action in actions]
    alert_count = sum(flagged)
    true_alerts = sum(1 for flag, label in zip(flagged, labels) if flag and label == 1)
    legitimate = labels.count(0)
    operational = {
        "test_positive_rate": round(sum(labels) / len(labels), 4) if labels else None,
        "alerts": alert_count,
        "alerts_per_1000_events": round(1000 * alert_count / len(labels), 1) if labels else None,
        "policy_precision": round(true_alerts / alert_count, 4) if alert_count else None,
        "policy_event_recall": round(true_alerts / sum(labels), 4) if sum(labels) else None,
        "false_alerts_per_1000_legitimate": round(1000 * (alert_count - true_alerts) / legitimate, 1) if legitimate else None,
        "prevalence_note": "Synthetic prevalence is far above real fraud prevalence, so precision here overstates deployment precision.",
    }
    return {
        "status": status,
        "operational": operational,
        "score_semantics": "uncalibrated_risk_index",
        "calibration_status": "NOT_FITTED",
        "selection_threshold": threshold,
        "threshold_rule": "canonical_policy" if threshold is None and status == "policy" else "calibration_only" if status == "fitted" else "fixed_b0_continuity",
        "budget": budget_metrics(scores, labels, event_keys=_event_keys(events), positive_story_count=len(positive_stories)),
        "pr_auc": pr_auc_unknown(scores, labels),
        "brier_uncalibrated_diagnostic": brier_unknown(scores, labels),
        "ece_uncalibrated_diagnostic": ece_unknown(scores, labels),
        "capacity_recall": _capacity_recall(scores, labels, 20),
        "policy": {
            "macro_f1": macro_f1_unknown(predictions, labels),
            "coverage": coverage_metrics(actions, labels, scores),
            "by_scenario": grouped_error_unknown(predictions, labels, [str(truth[event.event_id]["scenario"]) for event in events]),
            "by_institution": grouped_error_unknown(predictions, labels, [event.institution_id for event in events]),
            "story_detection": story_report,
            "duplicate_alert_ratio": duplicate_alert_ratio_by_story(events, truth, actions),
            "innocent_friction": innocent_friction_unknown(labels, actions),
        },
        "resources": resources,
        "metric_domains": "Budget/PR-AUC rank scores; policy metrics use actions. UNKNOWN is never backfilled. Unfitted HGB thresholds abstain.",
    }


def _percentiles(samples: list[float]) -> dict[str, float | None]:
    if not samples:
        return {"p50": None, "p95": None, "p99": None}
    values = sorted(samples)
    def pick(fraction: float) -> float:
        index = min(len(values) - 1, int(round(fraction * (len(values) - 1))))
        return round(values[index], 4)
    return {"p50": pick(0.50), "p95": pick(0.95), "p99": pick(0.99)}


def _latency_sample(event: PreAuthEventV2, context: ResearchContext) -> dict[str, Any]:
    samples = {name: [] for name in ("features_ms", "index_ms", "score_ms", "serialize_ms", "e2e_ms")}
    for _ in range(30):
        start = time.perf_counter()
        index_start = time.perf_counter()
        _history((*context.events, event), event)
        index_end = time.perf_counter()
        vector_start = time.perf_counter()
        b1 = B1Baseline.score(event, context)
        vector_end = time.perf_counter()
        score_start = time.perf_counter()
        decision = score_pre_auth_v2(event, context, server_now=event.occurred_at, execution_mode="LIVE_SYNTHETIC")
        score_end = time.perf_counter()
        encoded = json.dumps(decision.model_dump(mode="json"), sort_keys=True)
        end = time.perf_counter()
        _ = (b1, encoded)
        samples["features_ms"].append((vector_end - vector_start) * 1000)
        samples["index_ms"].append((index_end - index_start) * 1000)
        samples["score_ms"].append((score_end - score_start) * 1000)
        samples["serialize_ms"].append((end - score_end) * 1000)
        samples["e2e_ms"].append((end - start) * 1000)
    return {name: _percentiles(values) for name, values in samples.items()}


def _candidate_manifests(
    corpus: Mapping[str, Any],
    split_checksum: str,
    vector_checksum: str,
    out_dir: Path,
    *,
    hgb_threshold: float | None = None,
) -> dict[str, dict[str, Any]]:
    common = {
        "generator_version": corpus["manifest"]["generator_version"],
        "event_checksum": corpus["manifest"]["event_checksum"],
        "label_checksum": corpus["manifest"]["label_checksum"],
        "vector_checksum": vector_checksum,
        "split_checksum": split_checksum,
    }
    b0 = build_candidate_manifest(
        candidate="b0-v2", engine_version=RESEARCH_ENGINE, contract="b0.v2", seed=int(corpus["seed"]),
        unknown_policy="UNKNOWN rows are abstentions and are never ranked or backfilled",
        hyperparameters=B0Baseline.metadata.hyperparameters, lock_path=ROOT / "requirements-py312.lock", **common,
    )
    b1 = build_candidate_manifest(
        candidate="b1-v2", engine_version=RESEARCH_ENGINE, contract="motif.v2", seed=int(corpus["seed"]),
        unknown_policy="UNKNOWN rows are abstentions and are never ranked or backfilled",
        hyperparameters=B1Baseline.metadata.hyperparameters, lock_path=ROOT / "requirements-py312.lock", **common,
    )
    hgb = build_candidate_manifest(
        candidate="hgb-motif-v2", engine_version=RESEARCH_ENGINE, contract="motif.v2", seed=int(corpus["seed"]),
        unknown_policy="UNKNOWN rows are excluded from fit and are never ranked or backfilled",
        hyperparameters={"max_depth": 3, "max_iter": 40, "learning_rate": 0.1, "random_state": int(corpus["seed"])},
        threshold=hgb_threshold, lock_path=ROOT / "requirements-py312.lock",
        library_versions=resolved_library_versions(include_sklearn=True), **common,
    )
    write_candidate_manifest(out_dir / "research-registry-b0-v2.json", b0)
    write_candidate_manifest(out_dir / "research-registry-b1-v2.json", b1)
    write_candidate_manifest(out_dir / "research-registry-hgb-motif-v2.json", hgb)
    return {"b0": b0, "b1": b1, "hgb": hgb}


def run_sim2_evaluation(
    *,
    config: CorpusConfig | None = None,
    seed: int = 7,
    story_count: int | None = None,
    volume_target: int | None = None,
    calendar_days: int = 180,
    institutions: tuple[str, ...] = ("BANK_A", "BANK_B", "BANK_C"),
    scenario_mixture: Mapping[str, float] | None = None,
    held_out_morphology: str | None = "split_value",
    out_dir: Path | None = None,
) -> dict[str, Any]:
    """Run one corrected story-based evaluation; no v1 flags are reused."""
    if config is None:
        selected_story_count = 3000 if story_count is None and volume_target is None else story_count
        config = CorpusConfig(
            seed=seed,
            calendar_days=calendar_days,
            story_count=selected_story_count,
            volume_target=volume_target,
            institutions=institutions,
            scenario_mixture=scenario_mixture if scenario_mixture is not None else CorpusConfig().scenario_mixture,
            held_out_morphology=held_out_morphology,
        )
    corpus = generate_sim2_corpus(config)
    events = list(corpus["events"])
    truth_by_event = corpus["truth_by_event"]
    validate_truth_by_event(truth_by_event)
    splits = split_complete_stories(
        events,
        truth_by_event,
        stories=corpus["stories"],
        guard_seconds=corpus["manifest"]["guard_seconds"],
    )
    contexts = _contexts_for(events)
    context_by_id = {event.event_id: context for event, context in zip(events, contexts)}
    b0 = B0Baseline()
    b1 = B1Baseline()
    started = time.perf_counter()
    b0_scores, b0_resources = _measure_prediction(b0, events, contexts)
    b1_scores, b1_resources = _measure_prediction(b1, events, contexts)
    decisions = [score_pre_auth_v2(event, context, server_now=event.occurred_at) for event, context in zip(events, contexts)]
    elapsed = time.perf_counter() - started
    peak = max(b0_resources["tracemalloc_peak_bytes"], b1_resources["tracemalloc_peak_bytes"])
    actions = [decision.action.value for decision in decisions]
    vectors = [list(feature_vector_for_event(event, context, event.occurred_at).values) for event, context in zip(events, contexts)]
    vector_checksum = sha256_json({event.event_id: vector for event, vector in zip(events, vectors)})
    split_checksum = sha256_json({name: list(split.story_ids) for name, split in splits.items()})
    event_index = {event.event_id: index for index, event in enumerate(events)}
    train_events = _split_events(splits["train"])
    calibration_events = _split_events(splits["calibration"])
    fit_started = time.perf_counter()
    hgb = HGBBaseline(seed=config.seed).fit(
        train_events,
        [context_by_id[event.event_id] for event in train_events],
        _labels(train_events, truth_by_event),
    )
    hgb_fit_seconds = time.perf_counter() - fit_started
    hgb_calibration_scores = hgb.predict(
        calibration_events,
        [context_by_id[event.event_id] for event in calibration_events],
    )
    hgb.select_threshold(
        hgb_calibration_scores,
        _labels(calibration_events, truth_by_event),
        alerts_per_thousand=ALERTS_PER_THOUSAND,
    )
    test_events = _split_events(splits["test"])
    test_contexts = [context_by_id[event.event_id] for event in test_events]
    test_b0 = [b0_scores[event_index[event.event_id]] for event in test_events]
    test_b1 = [b1_scores[event_index[event.event_id]] for event in test_events]
    test_hgb, hgb_resources = _measure_prediction(hgb, test_events, test_contexts)
    hgb_resources["fit_seconds"] = round(hgb_fit_seconds, 6)
    test_decisions = [decisions[event_index[event.event_id]] for event in test_events]
    test_actions = [decision.action.value for decision in test_decisions]
    test_labels = _labels(test_events, truth_by_event)
    test_keys = _event_keys(test_events)
    test_policy_predictions = _policy_predictions(test_actions)
    test_scenarios = [str(truth_by_event[event.event_id]["scenario"]) for event in test_events]
    test_institutions = [event.institution_id for event in test_events]
    positive_story_count = len({
        truth_by_event[event.event_id]["story_id"]
        for event in test_events
        if truth_by_event[event.event_id]["label"] == 1
    })
    b0_budget = budget_metrics(test_b0, test_labels, event_keys=test_keys, positive_story_count=positive_story_count)
    b1_budget = budget_metrics(test_b1, test_labels, event_keys=test_keys, positive_story_count=positive_story_count)
    hgb_budget = budget_metrics(test_hgb, test_labels, event_keys=test_keys, positive_story_count=positive_story_count)
    b1_story = story_detection_metrics(test_events, truth_by_event, test_actions, scores=test_b1)
    positive_story_flags: dict[str, list[int]] = {}
    for story_id in splits["test"].story_ids:
        rows = [
            (event, action) for event, action in zip(test_events, test_actions)
            if truth_by_event[event.event_id]["story_id"] == story_id
        ]
        if any(truth_by_event[event.event_id]["label"] == 1 for event, _action in rows):
            positive_story_flags[story_id] = [int(any(action in ("STEP_UP", "ANALYST_REVIEW") for _event, action in rows))]
    b1_story["story_bootstrap_interval"] = story_bootstrap_interval(
        positive_story_flags,
        metric=lambda values: sum(values) / len(values) if values else None,
        seed=config.seed,
        replicates=200,
    )
    b0_actions = ["UNKNOWN" if score is None else "STEP_UP" if score >= 0.60 else "ALLOW" for score in test_b0]
    b0_story = story_detection_metrics(test_events, truth_by_event, b0_actions, scores=test_b0, b0_threshold=0.60)
    hgb_actions = ["UNKNOWN" if score is None or hgb.threshold is None else "STEP_UP" if score >= hgb.threshold else "ALLOW" for score in test_hgb]
    candidates = {
        "b0": _candidate_report(test_events, truth_by_event, test_b0, b0_actions, threshold=0.60, resources=b0_resources, status="fixed_baseline"),
        "b1": _candidate_report(test_events, truth_by_event, test_b1, test_actions, threshold=None, resources=b1_resources, status="policy"),
        "hgb": _candidate_report(test_events, truth_by_event, test_hgb, hgb_actions, threshold=hgb.threshold, resources=hgb_resources, status="fitted" if hgb.available else "unavailable"),
    }
    candidates["hgb"]["reason"] = hgb.reason
    diagnostics = {}
    for name, options in (("hub_outage", {"hub_available": False}), ("partial_visibility", {"visible_institutions": {config.institutions[0]}})):
        diagnostic_contexts = _contexts_for(events, **options)
        diagnostic_scores = b1.predict(events, diagnostic_contexts)
        diagnostic_actions = [score_pre_auth_v2(event, context, server_now=event.occurred_at).action.value for event, context in zip(events, diagnostic_contexts)]
        indices = [event_index[event.event_id] for event in test_events]
        diagnostics[name] = _candidate_report(test_events, truth_by_event, [diagnostic_scores[index] for index in indices], [diagnostic_actions[index] for index in indices], threshold=None, resources={}, status="policy")
    held_out_indices = [index for index, event in enumerate(test_events) if truth_by_event[event.event_id]["scenario"] == config.held_out_morphology]
    diagnostics["held_out_morphology"] = {
        "name": config.held_out_morphology,
        "eligible_n": len(held_out_indices),
        "b1_budget": budget_metrics([test_b1[index] for index in held_out_indices], [test_labels[index] for index in held_out_indices]),
    }
    adversarial = {
        "inventory": adversarial_inventory(events, truth_by_event),
        "delayed_forward": evaluate_policy_degradation(events, truth_by_event, _actions_for_stream),
        "partial_visibility_status": "measured_simulated_context",
        "hub_outage_status": "measured_simulated_context",
        "calibration_status": "mismatch/staleness is fail-closed in app.research.calibration",
    }
    policy_labels = test_labels
    scenario_policy = grouped_error_unknown(test_policy_predictions, policy_labels, test_scenarios)
    institution_policy = grouped_error_unknown(test_policy_predictions, policy_labels, test_institutions)
    metrics = {
        "data_status": "synthetic",
        "evaluation_version": "earlytrace-evaluation-sim-2",
        "seed": config.seed,
        "engine_version": RESEARCH_ENGINE,
        "feature_contracts": {"b0": "b0.v2", "b1": "motif.v2"},
        "generator_version": SIM2_VERSION,
        "neural_model_trained": False,
        "conformal_used": False,
        "rmse_optimized": False,
        "n_events": len(events),
        "n_stories": len(corpus["stories"]),
        "candidates": candidates,
        "diagnostics": diagnostics,
        "research_trust_boundary": "simulated consent; runtime signed-consent behavior is tested separately",
        "splits": {name: split.as_dict() for name, split in splits.items()},
        "temporal_test": {
            "n": len(test_events),
            "b0": b0_budget,
            "b1": b1_budget,
            "hgb": hgb_budget,
            "b0_pr_auc": pr_auc_unknown(test_b0, test_labels),
            "b1_pr_auc": pr_auc_unknown(test_b1, test_labels),
            "b0_brier_uncalibrated": brier_unknown(test_b0, test_labels),
            "b1_brier_uncalibrated": brier_unknown(test_b1, test_labels),
            "b1_ece_uncalibrated": ece_unknown(test_b1, test_labels),
            "capacity_recall": _capacity_recall(test_b1, test_labels, capacity=20),
        },
        "policy": {
            "macro_f1": macro_f1_unknown(test_policy_predictions, policy_labels),
            "by_scenario": scenario_policy,
            "by_institution": institution_policy,
            "coverage": coverage_metrics(test_actions, test_labels, test_b1),
            "story_detection": b1_story,
            "b0_story_detection": b0_story,
            "duplicate_alert_ratio": duplicate_alert_ratio_by_story(test_events, truth_by_event, test_actions),
            "innocent_friction": innocent_friction_unknown(test_labels, test_actions),
        },
        "support": {
            "eligible_n": len(test_labels),
            "scored_n": sum(score is not None for score in test_b1),
            "unknown_n": sum(score is None for score in test_b1),
            "positive_story_count": b1_story["positive_story_count"],
            "budget_support_status": b1_budget["budget_support_status"],
            "warning": "Synthetic descriptive evidence only; no population/generalisation claim.",
        },
        "research_baselines": {
            "b0": {"contract": "b0.v2", "calibrated": False},
            "b1": {"contract": "motif.v2", "calibrated": False},
            "hgb": {"available": hgb.available, "reason": hgb.reason, "threshold": hgb.threshold, "calibrated": False},
        },
        "latency_ms": _latency_sample(events[len(events) // 2], contexts[len(events) // 2]) if events else {},
        "resources": {
            "score_wall_seconds": round(elapsed, 4),
            "throughput_events_per_second": round(len(events) / elapsed, 3) if elapsed else None,
            "tracemalloc_peak_bytes": peak,
        },
        "adversarial": adversarial,
        "checksums": {
            "event_checksum": corpus["manifest"]["event_checksum"],
            "label_checksum": corpus["manifest"]["label_checksum"],
            "truth_checksum": truth_checksum(truth_by_event),
            "vector_checksum": vector_checksum,
            "split_checksum": split_checksum,
        },
        "unknown_metric_domain": "All valid labelled events remain in eligible_n; UNKNOWN is abstention, never ranked or budget-filled. PR-AUC/Brier/ECE are null when eligible rows are unscored.",
        "known_limit": "Metrics describe this synthetic generator and this run only.",
    }
    destination = out_dir or (ROOT / "data" / "evaluation" / f"sim2-seed{config.seed}-stories{len(corpus['stories'])}")
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "truth_by_event.json").write_text(json.dumps(truth_by_event, indent=2, sort_keys=True), encoding="utf-8")
    (destination / "manifest.json").write_text(json.dumps({
        **corpus["manifest"],
        "evaluation_version": "earlytrace-evaluation-sim-2",
        "engine_version": RESEARCH_ENGINE,
        "code_version": VERSION,
        "vector_checksum": vector_checksum,
        "split_checksum": split_checksum,
        "dependency_lock_hash": dependency_lock_hash(ROOT / "requirements-py312.lock"),
        "git_state": "not claimed by research evaluator",
    }, indent=2, sort_keys=True), encoding="utf-8")
    (destination / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    with (destination / "event-summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=("event_id", "occurred_at", "action", "score", "label"))
        writer.writeheader()
        for event, action, decision in zip(test_events, test_actions, test_decisions):
            writer.writerow({
                "event_id": event.event_id,
                "occurred_at": event.occurred_at.isoformat(),
                "action": action,
                "score": decision.score,
                "label": truth_by_event[event.event_id]["label"],
            })
    manifests = _candidate_manifests(corpus, split_checksum, vector_checksum, destination, hgb_threshold=hgb.threshold)
    metrics["research_manifests"] = {name: manifest["manifest_checksum"] for name, manifest in manifests.items()}
    (destination / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    return {"run_id": destination.name, "path": str(destination), "metrics": metrics, "manifest": corpus["manifest"], "corpus": corpus}


def _artifact_checksums(directory: Path) -> dict[str, str]:
    return {
        str(path.relative_to(directory)).replace("\\", "/"): sha256_file(path)
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def run_multi_seed(
    seeds: Sequence[int] = (7, 11, 23, 47, 89),
    *,
    story_count: int | None = 3000,
    volume_target: int | None = None,
    calendar_days: int = 180,
    institutions: tuple[str, ...] = ("BANK_A", "BANK_B", "BANK_C"),
    scenario_mixture: Mapping[str, float] | None = None,
    held_out_morphology: str | None = "split_value",
    out_root: Path | None = None,
) -> dict[str, Any]:
    """Run deterministic descriptive seeds under one checksumable run root."""
    requested_seeds = tuple(seeds)
    if not requested_seeds:
        raise ValueError("seeds must contain at least one integer")
    if len(set(requested_seeds)) != len(requested_seeds):
        raise ValueError("seeds must be unique")
    if any(isinstance(seed, bool) or not isinstance(seed, int) for seed in requested_seeds):
        raise ValueError("seeds must be integers")

    common_config = CorpusConfig(
        seed=requested_seeds[0],
        story_count=story_count,
        volume_target=volume_target,
        calendar_days=calendar_days,
        institutions=institutions,
        scenario_mixture=scenario_mixture,
        held_out_morphology=held_out_morphology,
    )
    common_configuration = common_config.as_dict()
    common_configuration.pop("seed")
    run_id = sha256_json({"seeds": list(requested_seeds), "configuration": common_configuration})[:16]
    run_name = f"sim2-multiseed-{run_id}"
    destination_root = Path(out_root) if out_root is not None else ROOT / "data" / "evaluation" / run_name
    destination_root.mkdir(parents=True, exist_ok=True)

    results: dict[int, dict[str, Any]] = {}
    statuses: list[dict[str, Any]] = []
    failures: dict[str, dict[str, str]] = {}
    for seed in requested_seeds:
        destination = destination_root / f"seed-{seed}"
        destination.mkdir(parents=True, exist_ok=True)
        config = CorpusConfig(
            seed=seed,
            story_count=story_count,
            volume_target=volume_target,
            calendar_days=calendar_days,
            institutions=institutions,
            scenario_mixture=scenario_mixture,
            held_out_morphology=held_out_morphology,
        )
        (destination / "config.json").write_text(
            json.dumps(config.as_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )
        try:
            result = run_sim2_evaluation(config=config, out_dir=destination)
        except Exception as exc:
            failure = {"type": type(exc).__name__, "message": str(exc)}
            failures[str(seed)] = failure
            statuses.append({
                "seed": seed,
                "status": "failed",
                "path": str(destination),
                "relative_path": str(destination.relative_to(destination_root)).replace("\\", "/"),
                "failure": failure,
                "checksums": _artifact_checksums(destination),
            })
            continue
        results[seed] = result
        statuses.append({
            "seed": seed,
            "status": "completed",
            "path": str(destination),
            "relative_path": str(destination.relative_to(destination_root)).replace("\\", "/"),
            "checksums": _artifact_checksums(destination),
        })

    precisions = {
        seed: result["metrics"]["temporal_test"]["b1"]["precision"]
        for seed, result in results.items()
    }
    b1_budget_precision = aggregate_seed_values(precisions)
    completed_seeds = [seed for seed in requested_seeds if seed in results]
    aggregate = {
        "aggregate_version": "earlytrace-sim-2-multiseed-v1",
        "run_id": run_name,
        "path": str(destination_root),
        "data_status": "synthetic",
        "provenance": "Synthetic payment-event simulator; not customer, UPI, bank, or NPCI data.",
        "configuration": {**common_configuration, "seeds": list(requested_seeds)},
        "seeds": list(requested_seeds),
        "seed_statuses": statuses,
        "completed_seeds": completed_seeds,
        "failed_seeds": [seed for seed in requested_seeds if str(seed) in failures],
        "failures": failures,
        "checksums": {str(row["seed"]): row["checksums"] for row in statuses},
        "aggregation": {
            "b1_budget_precision": b1_budget_precision,
            "candidates": {
                candidate: {
                    metric: aggregate_seed_values({seed: result["metrics"]["candidates"][candidate]["budget"][metric] for seed, result in results.items()})
                    for metric in ("precision", "recall", "budget_slots", "unknown_n")
                }
                for candidate in ("b0", "b1", "hgb")
            },
            "operational": {
                candidate: {
                    **{
                        metric: aggregate_seed_values({seed: result["metrics"]["candidates"][candidate]["operational"][metric] for seed, result in results.items()})
                        for metric in ("policy_precision", "policy_event_recall", "alerts_per_1000_events", "false_alerts_per_1000_legitimate")
                    },
                    "story_recall": aggregate_seed_values({seed: result["metrics"]["candidates"][candidate]["policy"]["story_detection"]["story_recall"] for seed, result in results.items()}),
                    "mean_lead_time_minutes": aggregate_seed_values({seed: result["metrics"]["candidates"][candidate]["policy"]["story_detection"]["mean_lead_time_minutes"] for seed, result in results.items()}),
                    "pr_auc": aggregate_seed_values({seed: result["metrics"]["candidates"][candidate]["pr_auc"]["value"] for seed, result in results.items()}),
                }
                for candidate in ("b0", "b1", "hgb")
            },
            "support_gate": "supported" if results and all(result["metrics"]["support"]["budget_support_status"] == "supported" for result in results.values()) and not failures else "insufficient_or_incomplete",
            "completed_seed_n": len(completed_seeds),
            "requested_seed_n": len(requested_seeds),
            "status": "descriptive_multi_seed" if completed_seeds else "no_completed_seeds",
        },
        "b1_budget_precision": b1_budget_precision,
        "results": {
            str(seed): {"path": result["path"], "metrics": result["metrics"]}
            for seed, result in results.items()
        },
        "claim": "descriptive multi-seed aggregation on synthetic data only; not a population/generalisation or scientific-win claim",
        "status": "completed" if not failures else "failed",
    }
    aggregate_path = destination_root / "aggregate.json"
    aggregate_path.write_text(json.dumps(aggregate, indent=2, sort_keys=True), encoding="utf-8")
    return {
        **aggregate,
        "aggregate_path": str(aggregate_path),
        "success": not failures,
    }


__all__ = ["ResearchContext", "run_multi_seed", "run_sim2_evaluation"]
