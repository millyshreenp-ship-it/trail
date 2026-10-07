from app.evaluation.run_sim2 import _context_for, _contexts_for
from app.simulator.sim2 import CorpusConfig, generate_sim2_corpus


def test_future_event_mutation_cannot_change_subject_vector():
    from app.detection.features_contract import feature_vector_for_event

    corpus = generate_sim2_corpus(CorpusConfig(seed=41, story_count=10, calendar_days=30))
    current = corpus["events"][0]
    context = _context_for(current, corpus["events"])
    before = feature_vector_for_event(current, context, current.occurred_at)
    later = current.model_copy(update={"event_id": "evt_future_boundary", "trace_id": "trace_future_boundary", "idempotency_key": "idem_future_boundary", "occurred_at": current.occurred_at.replace(year=2027), "as_of": current.occurred_at.replace(year=2027)})
    after = feature_vector_for_event(current, _context_for(current, [*corpus["events"], later]), current.occurred_at)
    assert before.values == after.values


def test_indexed_contexts_preserve_full_history_vectors_and_decisions():
    from app.detection.features_contract import feature_vector_for_event
    from app.detection.preauth import score_pre_auth_v2

    corpus = generate_sim2_corpus(CorpusConfig(seed=17, story_count=80))
    events = corpus["events"]
    indexed = _contexts_for(events)
    for event, context in zip(events, indexed):
        original = _context_for(event, events)
        assert feature_vector_for_event(event, context, event.occurred_at).values == feature_vector_for_event(event, original, event.occurred_at).values
        assert score_pre_auth_v2(event, context, server_now=event.occurred_at) == score_pre_auth_v2(event, original, server_now=event.occurred_at)
    assert sum(len(context.events) for context in indexed) < sum(len(_context_for(event, events).events) for event in events)
