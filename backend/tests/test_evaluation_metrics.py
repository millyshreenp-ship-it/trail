from app.evaluation.metrics_v2 import (
    brier_unknown,
    budget_metrics,
    ece_unknown,
    pr_auc_unknown,
    story_bootstrap_interval,
)


def test_unknown_rows_stay_in_denominator_and_never_fill_budget():
    result = budget_metrics(
        [0.9, None, 0.8, 0.1], [1, 1, 0, 0],
        alerts_per_thousand=500,
        event_keys=[("2026-01-01", "evt_a"), ("2026-01-02", "evt_b"), ("2026-01-03", "evt_c"), ("2026-01-04", "evt_d")],
    )
    assert result["eligible_n"] == 4
    assert result["scored_n"] == 3
    assert result["unknown_n"] == 1
    assert result["budget_slots"] == 2
    assert result["selected_alerts"] == 2
    assert result["unfilled_slots"] == 0
    assert "evt_b" not in result["selected_event_ids"]


def test_zero_slot_and_unscored_calibration_metrics_are_explicit():
    budget = budget_metrics([0.5], [1])
    assert budget["budget_slots"] == 0
    assert budget["precision"] is None
    assert budget["recall"] == 0.0
    assert budget["budget_support_status"] == "no_budget_slot"
    assert pr_auc_unknown([0.5, None], [1, 0])["value"] is None
    assert brier_unknown([0.5, None], [1, 0])["value"] is None
    assert ece_unknown([0.5, None], [1, 0])["value"] is None


def test_bootstrap_samples_complete_story_units():
    result = story_bootstrap_interval(
        {"story_a": [1, 0], "story_b": [0, 0]},
        metric=lambda rows: sum(rows) / len(rows),
        seed=3,
        replicates=20,
    )
    assert result["unit"] == "complete_story"
    assert result["replicates"] == 20
    assert result["ci_status"] == "descriptive"
