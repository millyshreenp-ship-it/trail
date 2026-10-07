"""Offline research smoke using only the in-repository tiny sim-2 fixture."""
from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

_TRAIL_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_TRAIL_ROOT / "backend"))

from app.research.guards import assert_safe_local_path, network_disabled
from app.research.manifests import build_candidate_manifest, sha256_json, write_candidate_manifest
from app.simulator.sim2 import CorpusConfig, generate_sim2_corpus


def run_smoke(output_dir: str | Path | None = None) -> dict:
    requested = Path(output_dir).resolve() if output_dir else _TRAIL_ROOT / "research" / "kaggle" / "runs" / "tiny-fixture"
    destination = assert_safe_local_path(
        requested,
        root=requested.parent if output_dir else _TRAIL_ROOT,
    )
    destination.mkdir(parents=True, exist_ok=True)
    config = CorpusConfig(story_count=12, calendar_days=30, held_out_morphology="split_value")
    with network_disabled():
        corpus = generate_sim2_corpus(config)
        manifest = build_candidate_manifest(
            candidate="b0-v2-smoke",
            engine_version="earlytrace-b0b1-heuristic-v2",
            contract="b0.v2",
            generator_version=corpus["manifest"]["generator_version"],
            event_checksum=corpus["manifest"]["event_checksum"],
            label_checksum=corpus["manifest"]["label_checksum"],
            vector_checksum=sha256_json({"fixture": "tiny", "vectors": "not-scored"}),
            split_checksum=sha256_json(corpus["manifest"]["split_boundaries"]),
            seed=config.seed,
            unknown_policy="UNKNOWN is abstention; no budget backfill",
            hyperparameters={"smoke": True},
            lock_path=_TRAIL_ROOT / "requirements-py312.lock",
            library_versions={"python": platform.python_version()},
        )
        (destination / "config.json").write_text(json.dumps(config.as_dict(), indent=2, sort_keys=True), encoding="utf-8")
        (destination / "manifest.json").write_text(json.dumps(corpus["manifest"], indent=2, sort_keys=True), encoding="utf-8")
        (destination / "metrics.json").write_text(json.dumps({
            "data_status": "synthetic",
            "events": len(corpus["events"]),
            "stories": len(corpus["stories"]),
            "external_datasets": [],
            "network": "disabled",
            "uploads": False,
            "fixture_source": "in_repo_only",
            "candidate_status": "smoke_only_insufficient_evidence",
        }, indent=2, sort_keys=True), encoding="utf-8")
        write_candidate_manifest(destination / "candidate-manifest.json", manifest)
    return {"path": str(destination), "events": len(corpus["events"]), "stories": len(corpus["stories"]), "status": "smoke_only"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Local offline EarlyTrace research smoke")
    parser.add_argument("--out", default="")
    args = parser.parse_args()
    print(json.dumps(run_smoke(args.out or None), indent=2))


if __name__ == "__main__":
    main()
