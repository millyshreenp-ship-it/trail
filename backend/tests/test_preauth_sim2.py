from app.simulator.sim2 import CorpusConfig, generate_sim2_corpus


def test_sim2_is_deterministic_and_truth_is_a_sidecar():
    a = generate_sim2_corpus(CorpusConfig(seed=31, story_count=12, calendar_days=30))
    b = generate_sim2_corpus(CorpusConfig(seed=31, story_count=12, calendar_days=30))
    assert [event.model_dump(mode="json") for event in a["events"]] == [event.model_dump(mode="json") for event in b["events"]]
    assert a["truth_by_event"] == b["truth_by_event"]
    assert all(not hasattr(event, "label") and not hasattr(event, "story_id") for event in a["events"])
    assert all(event.source_token.startswith("tok_") and event.payee_token.startswith("tok_") for event in a["events"])
    assert a["manifest"]["generator_version"] == "earlytrace-sim-2"


def test_sim2_volume_target_keeps_complete_stories():
    corpus = generate_sim2_corpus(CorpusConfig(seed=32, story_count=None, volume_target=20, calendar_days=30))
    assert len(corpus["events"]) >= 20
    for story in corpus["stories"]:
        assert story["event_ids"]
        assert all(event_id in corpus["truth_by_event"] for event_id in story["event_ids"])


def test_sim2_config_rejects_ambiguous_controls_and_mixture():
    try:
        CorpusConfig(story_count=3, volume_target=10)
    except ValueError as exc:
        assert "mutually exclusive" in str(exc)
    else:
        raise AssertionError("simultaneous volume controls were accepted")
    try:
        CorpusConfig(story_count=3, scenario_mixture={"unknown": 1.0})
    except ValueError as exc:
        assert "unknown scenario" in str(exc)
    else:
        raise AssertionError("unknown mixture key was accepted")


def test_sim2_urgency_is_not_a_perfect_label_shortcut():
    corpus = generate_sim2_corpus(CorpusConfig(seed=17, story_count=200))
    urgent_labels = {corpus["truth_by_event"][event.event_id]["label"] for event in corpus["events"] if event.session_context.value == "URGENT_SOCIAL_ENGINEERING"}
    assert urgent_labels == {0, 1}
    assert corpus["manifest"]["scenario_revision"] == "lookalikes-v2"


def test_hgb_rejects_mismatched_contract_without_fitting():
    from app.research.baselines import HGBBaseline

    baseline = HGBBaseline().fit([], [], [], expected_feature_hash="0" * 64)
    assert baseline.available is False
    assert baseline.reason == "feature_contract_mismatch"
