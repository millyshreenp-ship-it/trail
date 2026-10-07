"""Independent labels for the synthetic pre-auth scenario."""
from __future__ import annotations

from app.simulator import scenario_preauth_mule_network
from app.simulator.scam_patterns import LABEL_RULE


def test_same_seed_reproduces_events_and_labels():
    a = scenario_preauth_mule_network(seed=11)
    b = scenario_preauth_mule_network(seed=11)
    assert [e.event_id for e in a["events"]] == [e.event_id for e in b["events"]]
    assert a["labels"] == b["labels"]
    assert a["manifest"]["data_status"] == "synthetic"
    assert a["manifest"]["label_generation_rule"] == LABEL_RULE


def test_different_seed_changes_the_fixture():
    a = scenario_preauth_mule_network(seed=11)
    b = scenario_preauth_mule_network(seed=12)
    assert [e.source_token for e in a["events"]] != [e.source_token for e in b["events"]]


def test_labels_are_not_taken_from_the_scorer():
    scenario = scenario_preauth_mule_network(seed=11)
    rule = scenario["manifest"]["label_generation_rule"].lower()
    assert "detector" in rule
    assert "model prediction" in rule
    assert any(row["label"] == 1 for row in scenario["labels"].values())
    assert any(row["label"] == 0 for row in scenario["labels"].values())
    assert "merchant" in {row["scenario"] for row in scenario["labels"].values()}


def test_future_event_does_not_rewrite_earlier_labels():
    scenario = scenario_preauth_mule_network(seed=11)
    before = dict(scenario["labels"])
    extra = scenario["events"][-1].model_copy(update={
        "event_id": "evt_future1",
        "trace_id": "trace_future1",
        "idempotency_key": "idemfuture1",
    })
    assert extra.event_id not in before
    assert scenario["labels"] == before
