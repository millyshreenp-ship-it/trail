"""Portable synthetic-only benchmark entry point."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.evaluation.run_sim2 import run_multi_seed
from app.research.guards import network_disabled


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stories", type=int, default=3000)
    parser.add_argument("--seeds", default="7,11,23,47,89")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    seeds = tuple(int(seed.strip()) for seed in args.seeds.split(","))
    with network_disabled():
        result = run_multi_seed(seeds, story_count=args.stories, out_root=args.out)
    print(json.dumps({"status": result["status"], "aggregate_path": result["aggregate_path"], "claim": result["claim"]}))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())