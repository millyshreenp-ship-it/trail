# Evaluation protocol

## Reported benchmark (synthetic, 5-seed)

The reported engine is `earlytrace-b0b1-heuristic-v2`. Regenerate with:

```text
python research/kaggle/run.py --stories 3000 --out data/evaluation/sim2-multiseed-product-v2
```

Output: `data/evaluation/sim2-multiseed-product-v2/aggregate.json`; seeds 7, 11, 23, 47, 89; 3,000 stories/seed; `support_gate: supported`. Seed 7 has 9,536 events and a 1,872-event temporal test window. All data is **synthetic**; scores are **uncalibrated** risk indices; no neural or conformal claim is made.

The frozen v1 evaluator (`earlytrace-b0b1-heuristic-v1`) remains for regression only. Its single-seed run had **one alert** at the 20-per-1,000 budget and is not stable evidence; it is superseded by the 5-seed benchmark above. Latency figures throughout are unloaded in-process samples, **not a loaded service SLO**.

## Results

| Metric | B0 | B1 | HGB |
|---|---:|---:|---:|
| Alert-budget precision (20/1k, ~37.6 slots) | 1.0 | 1.0 | 1.0 |
| Alert-budget recall | 0.038 | 0.038 | 0.038 |
| Story recall (5-seed mean) | 0.0 | 0.615 | 0.422 |
| Mean lead time | — | 73 min | ~1 min |
| False friction | 0.0 | 0.052 | 0.0 |
| Innocent review | 0.0 | 0.016 | 0.0 |
| Event PR-AUC (uncalibrated) | 0.954 | 0.892 | 0.966 |

The alert-budget row is a budget-limited **tie**; the models are not ranked on it. Lead the reporting with story recall, lead time, and false friction, plus a story-recall-vs-alerts-per-1,000 curve. Degradation (seed 7, B1): hub outage story recall 0.46, partial visibility 0.587. B0's fixed 0.60 threshold never fires, so its story recall is 0.0 (a baseline limitation).

## Splits and truth boundary

1. Temporal: earlier events train, a later window calibrates, the latest window tests; boundaries recorded in the manifest.
2. Inductive: account tokens held out with a stable HMAC bucket, never Python's salted `hash()`.
3. Open-set: the split-value story family is held out (held-out morphology).
4. Partial participation: a BANK_A-only slice compared with the expected institution set.
5. Legitimate stress: merchant, household, rent, salary, refund, safe new payee, pass-through, **urgent legitimate lookalikes**, and **disguised non-urgent scams**.
6. Future, equal-time, and current-event records are excluded by the shared event-time history primitive. Planted roles/labels remain an evaluator-only sidecar joined after scoring; detector features never receive truth fields.

The v2 plan uses complete stories, fixed 60/20/20 story-start partitions, and a guard of maximum declared story duration plus 24 hours.

## Metric domains and operating point

The primary operating point is precision/recall at 20 alerts per 1,000 eligible test events, with lead time from the first step-up/review to the last planted-positive story event. PR-AUC, coverage/UNKNOWN, selective risk, scenario/institution FPR/FNR, macro-F1, uncalibrated Brier/ECE, false friction, innocent review, duplicate alerts, latency/resources, and adversarial degradation are secondary diagnostics.

Every valid labelled event remains in `eligible_n`. UNKNOWN is abstention: it contributes to coverage and recall denominators, is never ranked, and never backfills an alert slot. Reports expose `budget_slots`, `selected_alerts`, `unfilled_slots`, `scored_n`, `unknown_n`, and support status. No metric silently filters UNKNOWN or invents a score.

## Calibration and data rights

Runtime scores are risk indices, not probabilities. A calibration artifact may be used only after engine/feature/data/split/artifact checks pass; otherwise status is `NOT_FITTED`, `REJECTED`, or `UNAVAILABLE`. Split-conformal coverage is not claimed because payment events are not assumed exchangeable.

Only synthetic data from this repository is approved. External dataset **rights and checksums** (IEEE-CIS, Elliptic, IBM AML) are unresolved or pending; they must not be joined to EarlyTrace tokens, republished, or uploaded to Kaggle. **No Kaggle** or cloud credential is used by the evaluator.

## What is not a result

A neural model, a larger external dataset, an RMSE value, or an unrecorded figure is not an EarlyTrace result. The system makes no **production**, live-payment, **DPDP**-compliant, or scientific-baseline-win claim, and takes **no automatic** freeze/reject/reverse/report action.
