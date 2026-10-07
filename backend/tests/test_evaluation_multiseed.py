import json

from app.evaluation.run_sim2 import run_multi_seed
from app.simulator.sim2 import SCENARIO_KINDS


def test_multi_seed_writes_shared_root_config_and_aggregate(tmp_path):
    mixture = {name: 1 / len(SCENARIO_KINDS) for name in SCENARIO_KINDS}
    root = tmp_path / "sim2-multiseed-test"
    result = run_multi_seed(
        seeds=(7, 11),
        story_count=12,
        calendar_days=30,
        institutions=("BANK_A", "BANK_B", "BANK_C"),
        scenario_mixture=mixture,
        held_out_morphology="split_value",
        out_root=root,
    )

    aggregate = json.loads((root / "aggregate.json").read_text(encoding="utf-8"))
    assert result["success"] is True
    assert aggregate["data_status"] == "synthetic"
    assert aggregate["seeds"] == [7, 11]
    assert aggregate["failed_seeds"] == []
    assert set(aggregate["aggregation"]["candidates"]) == {"b0", "b1", "hgb"}
    assert set(aggregate["aggregation"]["operational"]) == {"b0", "b1", "hgb"}
    assert "false_alerts_per_1000_legitimate" in aggregate["aggregation"]["operational"]["b1"]
    assert aggregate["aggregation"]["support_gate"] == "insufficient_or_incomplete"
    assert aggregate["configuration"]["calendar_days"] == 30
    assert aggregate["configuration"]["institutions"] == ["BANK_A", "BANK_B", "BANK_C"]
    assert "scientific win" not in aggregate["claim"]
    for seed in (7, 11):
        seed_root = root / f"seed-{seed}"
        assert (seed_root / "config.json").exists()
        assert (seed_root / "manifest.json").exists()
        assert (seed_root / "truth_by_event.json").exists()
        assert (seed_root / "metrics.json").exists()
        config = json.loads((seed_root / "config.json").read_text(encoding="utf-8"))
        assert config["seed"] == seed
        assert config["calendar_days"] == 30
        assert config["scenario_mixture"] == mixture
        assert str(seed) in aggregate["checksums"]
        metrics = json.loads((seed_root / "metrics.json").read_text(encoding="utf-8"))
        for candidate in metrics["candidates"].values():
            assert candidate["calibration_status"] == "NOT_FITTED"
            assert candidate["budget"]["eligible_n"] == metrics["temporal_test"]["n"]
            assert "story_bootstrap_interval" in candidate["policy"]["story_detection"]
        assert "hub_outage" in metrics["diagnostics"]


def test_multi_seed_run_id_is_deterministic(tmp_path):
    kwargs = {"seeds": (7, 11), "story_count": 6, "calendar_days": 30}
    first = run_multi_seed(out_root=tmp_path / "first", **kwargs)
    second = run_multi_seed(out_root=tmp_path / "second", **kwargs)
    assert first["run_id"] == second["run_id"]
