from app.evaluation.splits import split_complete_stories
from app.simulator.sim2 import CorpusConfig, generate_sim2_corpus


def test_complete_story_temporal_split_is_disjoint_and_held_out():
    corpus = generate_sim2_corpus(CorpusConfig(seed=17, story_count=20, calendar_days=45))
    splits = split_complete_stories(
        corpus["events"], corpus["truth_by_event"], stories=corpus["stories"],
        guard_seconds=corpus["manifest"]["guard_seconds"],
    )
    assert {len(split.story_ids) for split in splits.values()} == {12, 4}
    assert not (set(splits["train"].story_ids) & set(splits["calibration"].story_ids))
    assert not (set(splits["train"].story_ids) & set(splits["test"].story_ids))
    assert not (set(splits["calibration"].story_ids) & set(splits["test"].story_ids))
    train_cal = {row["scenario"] for row in corpus["stories"] if row["partition"] != "test"}
    assert "split_value" not in train_cal
    assert any(row["scenario"] == "split_value" for row in corpus["stories"] if row["partition"] == "test")


def test_story_split_rejects_missing_truth_row():
    corpus = generate_sim2_corpus(CorpusConfig(seed=18, story_count=6, calendar_days=30))
    truth = dict(corpus["truth_by_event"])
    truth.pop(next(iter(truth)))
    try:
        split_complete_stories(corpus["events"], truth, stories=corpus["stories"])
    except ValueError as exc:
        assert "every valid event" in str(exc)
    else:
        raise AssertionError("missing truth row was accepted")
