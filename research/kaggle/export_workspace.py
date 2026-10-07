"""Generate minimized console replay from a completed synthetic benchmark."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.context.preauth import ContextFailure
from app.detection.preauth import score_pre_auth_v2
from app.evaluation.run_sim2 import _context_for
from app.security.tokens import TokenService
from app.simulator.sim2 import CorpusConfig, generate_sim2_corpus


def export(benchmark: Path, destination: Path):
    aggregate = json.loads((benchmark / "aggregate.json").read_text(encoding="utf-8"))
    if aggregate["status"] != "completed" or aggregate["data_status"] != "synthetic":
        raise ValueError("completed synthetic benchmark required")
    seed = aggregate["completed_seeds"][0]
    configuration = json.loads((benchmark / f"seed-{seed}" / "config.json").read_text(encoding="utf-8"))
    controls = {name: configuration[name] for name in ("seed", "story_count", "volume_target", "calendar_days", "institutions", "scenario_mixture", "held_out_morphology")}
    corpus = generate_sim2_corpus(CorpusConfig(**controls))
    saved = json.loads((benchmark / f"seed-{seed}" / "manifest.json").read_text(encoding="utf-8"))
    if corpus["manifest"]["event_checksum"] != saved["event_checksum"]:
        raise ValueError("generator does not reproduce the benchmark")
    tokens = TokenService(b"workspace-replay-pseudonyms-v2-only")
    cases = []
    selections = (("merchant_burst", "Merchant checkout burst"), ("new_beneficiary", "Urgent new beneficiary"), ("fanout", "Rapid onward distribution"), ("safe_new_payee", "Legitimate new beneficiary"), ("pass_through", "Salary and rent payment"), ("partial_visibility", "Corroboration unavailable"))
    for scenario, title in selections:
        story = next(story for story in corpus["stories"] if story["scenario"] == scenario and story["partition"] == "test")
        story_events = [event for event in corpus["events"] if event.event_id in story["event_ids"]]
        event = story_events[-1] if scenario != "new_beneficiary" else story_events[0]
        context = _context_for(event, corpus["events"], expected_institutions=frozenset({event.institution_id}))
        if scenario == "partial_visibility":
            context = replace(context, failure_code=ContextFailure.UNAVAILABLE, local_sufficient=False, evidence_coverage=0.0, events=())
        decision = score_pre_auth_v2(event, context, server_now=event.occurred_at).model_dump(mode="json")
        decision["audit_id"] = None
        graph_events = [prior for prior in context.events if prior.event_id in story["event_ids"]]
        nodes = {}
        edges = []
        for transfer in [*graph_events, event]:
            for token in (transfer.source_token, transfer.payee_token):
                identifier = tokens.to_case_display_pseudonym(event.event_id, token)
                nodes[identifier] = {"id": identifier, "label": "Subject payee" if token == event.payee_token else "Counterparty", "institution": transfer.institution_id, "subject": token == event.payee_token}
            edges.append({"id": transfer.event_id, "source": tokens.to_case_display_pseudonym(event.event_id, transfer.source_token), "target": tokens.to_case_display_pseudonym(event.event_id, transfer.payee_token), "occurred_at": transfer.occurred_at.isoformat(), "amount_bucket": transfer.amount_bucket, "pending": transfer.event_id == event.event_id})
        cases.append({"id": scenario, "title": title, "institution": event.institution_id, "amount_bucket": event.amount_bucket, "decision": decision, "nodes": list(nodes.values()), "edges": edges, "audit": [], "event_source": "OFFLINE_SYNTHETIC_REPLAY", "excluded_future_events": True})
    payload = {"schema_version": "earlytrace.workspace.v2", "data_status": "synthetic", "cases": cases, "benchmark": {"run_id": aggregate["run_id"], "configuration": aggregate["configuration"], "aggregation": aggregate["aggregation"], "completed_seeds": aggregate["completed_seeds"], "claim": aggregate["claim"]}}
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return {"cases": len(cases), "destination": str(destination)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "frontend" / "src" / "data" / "workspace-replay.json")
    args = parser.parse_args()
    print(json.dumps(export(args.benchmark, args.out)))