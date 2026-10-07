"""Dependency-gated graph research status, never imported by API startup."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    aggregate = json.loads((args.benchmark_root / "aggregate.json").read_text(encoding="utf-8"))
    if aggregate.get("data_status") != "synthetic" or aggregate.get("status") != "completed":
        raise ValueError("a completed synthetic benchmark is required")
    missing = [name for name in ("torch", "torch_geometric") if importlib.util.find_spec(name) is None]
    status = "skipped_dependency_missing" if missing else "not_evaluated_requires_separate_causal_graph_protocol"
    args.out.mkdir(parents=True, exist_ok=True)
    payload = {"status": status, "missing_dependencies": missing, "trained": False, "production_import": False, "benchmark_run_id": aggregate["run_id"]}
    (args.out / "graph-model-status.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload))


if __name__ == "__main__":
    main()