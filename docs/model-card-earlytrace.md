# Model card — EarlyTrace

## Summary

EarlyTrace is a **synthetic-only**, advisory, pre-authorisation scam-pattern recogniser. The runtime engine is a hand-built heuristic policy, not a trained neural model. Runtime scores are **uncalibrated** risk indices (`score_kind=RISK_INDEX`, `calibrated=false`), not probabilities. All measured numbers come from synthetic data we generated and are descriptive, not generalisable. No production, DPDP, real UPI/bank/NPCI, calibrated-probability, neural/GNN/TGN, or scientific-win claim is made.

## Models in the system

- **B0** — six-feature weighted heuristic.
- **B1** — temporal-motif policy with a strict event-time boundary (the API default).
- **HGB** — a histogram gradient-boosting candidate evaluated offline only; not loaded into the API.
- Engine id `earlytrace-b0b1-heuristic-v2`, contracts `b0.v2` / `motif.v2`. Calibration status is `NOT_FITTED` unless a fully compatible verified calibration artifact is loaded.
- The frozen compatibility baseline `earlytrace-b0b1-heuristic-v1` / `motif.v1` remains only for the offline v1 evaluator regression. All reported numbers below are from the v2 5-seed benchmark, not v1.

## Measured performance (synthetic, 5-seed)

Source: `data/evaluation/sim2-multiseed-product-v2/aggregate.json`; seeds 7, 11, 23, 47, 89; 3,000 stories/seed; `support_gate: supported`. Seed 7 has 9,536 events and a 1,872-event temporal test window.

At the 20-per-1,000 alert budget (~37.6 slots) B0, B1, and HGB each have precision 1.0 and recall 0.038 — a budget-limited **tie**; the models are not ranked on it. (This replaces the earlier single-seed v1 operating point, which rested on **one alert** and was not stable evidence.)

Story-level, mean of five seeds (~318 positive stories each):

| Model | Story recall | Mean lead time | False friction | Innocent review | Event PR-AUC (uncalibrated) |
|---|---:|---:|---:|---:|---:|
| B0 | 0.0 (fixed 0.60 threshold never fires — baseline limitation) | — | 0.0 | 0.0 | 0.954 |
| B1 | 0.615 | 73 min (conditional on detected stories) | 0.052 | 0.016 | 0.892 |
| HGB | 0.422 | ~1 min | 0.0 | 0.0 | 0.966 |

UNKNOWN rate is 0.0 on this corpus. Degradation (seed 7, B1): hub outage story recall 0.46; partial visibility 0.587. Latency p50 is 0.040 ms (B0/B1) and 0.823 ms (HGB); these are unloaded in-process microbenchmarks, **not a service SLO** and not a loaded benchmark.

## Intended use and users

A bank/PSP fraud analyst reviewing an urgent payment to a new beneficiary before rapid onward movement. The output is advisory: `ALLOW`, `WARN_AND_VERIFY`, `STEP_UP`, `ANALYST_REVIEW`, or `UNKNOWN`. A human makes every decision.

## Data and privacy

Only the in-repo synthetic generator and registered sandbox/staging fixtures are accepted. Tokens are **pseudonymous, not anonymous** if linked outside this system. The contract excludes voice/audio, SMS/WhatsApp/transcripts, contacts, phone/email/VPA, raw account/reference identifiers, exact amounts, credentials/OTP/PIN/MPIN, device fingerprints, and IP data. No live bank, NPCI, UPI-switch, cloud, or customer connector exists. External dataset **rights and checksums** (e.g. IEEE-CIS, Elliptic) are unresolved; **no Kaggle** download, upload, redistribution, or token join is performed.

## UNKNOWN (abstention)

`UNKNOWN` is returned for missing/invalid/expired/revoked/conflicting consent, stale or future events, insufficient history/evidence, unavailable/conflicting context, unsupported schema, or unusable calibration. A hub outage may yield `LOCAL_ONLY` with a step-up ceiling. UNKNOWN never invents a score and never backfills an alert slot.

## Known failures and false negatives

A first-time mule with no onward payment may only produce a verification step-up. Fan-in before cash-out, delayed hops beyond the motif window, partial visibility, hub outage, and stale/missing consent can remain quiet or UNKNOWN. B1 misses ~38% of positive stories. False friction is measured only on synthetic legitimate lookalikes; it is not a population estimate.

## Actions the model cannot take

EarlyTrace has **no automatic** freeze, reject, reverse, hold, accusation, police/I4C/NPCI report, or account report. Human display/review/step-up/escalation receipts are **record-only** (`effect=recorded_only`); feedback is quarantined and `applied_to_model=false`. The `production` profile intentionally refuses to start. Legacy Cases is a separately labelled complaint / institution-executed workflow.
