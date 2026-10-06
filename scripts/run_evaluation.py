"""Run the siloed-vs-Trail evaluation on the synthetic world and write the artefacts.

Usage (repo root):
    PYTHONPATH=backend python scripts/run_evaluation.py
    PYTHONPATH=backend python scripts/run_evaluation.py --complaint-rate 0.5 --no-write

Writes (unless --no-write):
    data/synthetic/transactions.jsonl       the generated corpus (gitignored)
    data/synthetic/ground_truth.json        labels + ring metadata (gitignored)
    data/synthetic/evaluation.json          machine-readable results (gitignored)
    docs/evaluation.md                      human-readable report (committed)
Synthetic data only.
"""
import argparse
import json
import pathlib

from app.detection.evaluation import EvalConfig, run_evaluation
from app.simulator import generate_dataset, write_synthetic_jsonl

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--legit", type=int, default=5000)
    ap.add_argument("--suspicious", type=int, default=500)
    ap.add_argument("--complaint-rate", type=float, default=1.0)
    ap.add_argument("--complaint-delay-min", type=float, default=30.0)
    ap.add_argument("--no-write", action="store_true")
    a = ap.parse_args()

    data = generate_dataset(n_legitimate=a.legit, n_suspicious=a.suspicious, seed=a.seed)
    report = run_evaluation(
        data, EvalConfig(complaint_rate=a.complaint_rate, complaint_delay_min=a.complaint_delay_min)
    )
    md = report.to_markdown()
    print(md)
    if a.no_write:
        return
    out = ROOT / "data" / "synthetic"
    n = write_synthetic_jsonl(out / "transactions.jsonl", data["transactions"])
    (out / "ground_truth.json").write_text(json.dumps(
        {"labels": data["labels"], "ring_meta": data["ring_meta"], "meta": data["meta"]}, indent=1))
    (out / "evaluation.json").write_text(json.dumps(report.to_dict(), indent=1))
    (ROOT / "docs" / "evaluation.md").write_text(md)
    print(f"wrote {n} transactions to {out}/ and docs/evaluation.md")


if __name__ == "__main__":
    main()
