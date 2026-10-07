import argparse
import json

import pytest

from app.evaluation.run_synthetic import _build_parser, _normalise_sim2_args
from app.simulator.sim2 import SCENARIO_KINDS


VALID_MIXTURE = json.dumps({name: 1 / len(SCENARIO_KINDS) for name in SCENARIO_KINDS})


def _normalise(argv):
    parser = _build_parser()
    return _normalise_sim2_args(parser.parse_args(argv), parser)


def test_sim2_normalises_all_common_controls():
    controls = _normalise([
        "--mode", "sim2", "--seeds", "7,11", "--story-count", "12",
        "--calendar-days", "30", "--institutions", "BANK_A,BANK_B,BANK_C",
        "--mixture", VALID_MIXTURE, "--held-out-morphology", "split_value",
    ])
    assert controls["seeds"] == (7, 11)
    assert controls["story_count"] == 12
    assert controls["volume_target"] is None
    assert controls["calendar_days"] == 30
    assert controls["institutions"] == ("BANK_A", "BANK_B", "BANK_C")
    assert controls["scenario_mixture"] == {name: 1 / 13 for name in SCENARIO_KINDS}
    assert controls["held_out_morphology"] == "split_value"


@pytest.mark.parametrize(
    "argv",
    [
        ["--mode", "sim2", "--mixture", "{"],
        ["--mode", "sim2", "--mixture", json.dumps({"unknown": 1.0})],
        ["--mode", "sim2", "--mixture", json.dumps({name: 1 / 13 for name in SCENARIO_KINDS if name != "fanout"})],
        ["--mode", "sim2", "--mixture", json.dumps({**{name: 1 / 13 for name in SCENARIO_KINDS}, "fanout": True})],
        ["--mode", "sim2", "--mixture", json.dumps({**{name: 1 / 13 for name in SCENARIO_KINDS}, "fanout": -1.0})],
        ["--mode", "sim2", "--mixture", "{" + ",".join(f'\"{name}\":0.1' for name in SCENARIO_KINDS) + "}"],
        ["--mode", "sim2", "--seeds", "7,,11"],
        ["--mode", "sim2", "--seeds", "7,7"],
        ["--mode", "sim2", "--story-count", "0"],
        ["--mode", "sim2", "--story-count", "2", "--volume-target", "10"],
        ["--mode", "sim2", "--calendar-days", "0"],
        ["--mode", "sim2", "--institutions", "BANK_B,BANK_A"],
        ["--mode", "sim2", "--institutions", "BANK_A,,BANK_B"],
        ["--mode", "sim2", "--days", "24"],
        ["--seeds", "7,11"],
    ],
)
def test_strict_sim2_controls_are_rejected(argv):
    with pytest.raises(SystemExit):
        _normalise(argv)


def test_v1_compatibility_parser_keeps_no_mode_rail():
    controls = _normalise(["--seed", "7", "--days", "24"])
    assert controls == {"mode": "v1", "seed": 7, "days": 24}
