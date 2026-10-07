# Data manifest

## Provenance

The sim2 generator (`backend/app/simulator/sim2.py`) and the frozen v1 generator create **synthetic** payment events in-process. No real UPI, bank, customer, NPCI, or switch data is present. Labels are planted story roles, held in an evaluator-only truth sidecar, and are never detector output or detector features.

The reported benchmark is `data/evaluation/sim2-multiseed-product-v2` (engine `earlytrace-b0b1-heuristic-v2`): seeds 7, 11, 23, 47, 89; 3,000 stories/seed; `support_gate: supported`. Seed 7 has 9,536 events and a 1,872-event temporal test window. At the 20-per-1,000 budget B0/B1/HGB tie at precision 1.0, recall 0.038. Story-level means: B0 recall 0.0, B1 0.615 (lead 73 min), HGB 0.422 (lead ~1 min); event PR-AUC 0.954/0.892/0.966, all **uncalibrated**. These are descriptive synthetic evidence, not generalisation or production results. The earlier v1 run rested on **one alert** and is superseded. The simulator now includes legitimate urgent lookalikes and disguised (non-urgent) scams so urgency is not a perfect label shortcut.

## Licence decision

| Source | Decision |
|---|---|
| EarlyTrace synthetic generator (sim2 + v1) | Use. Created in this repository; not real UPI or bank data. |
| IEEE-CIS Fraud Detection | **Rights/checksums** unresolved; do not preprocess, redistribute, or upload. |
| Elliptic | **Rights/checksums** unresolved; do not preprocess, redistribute, or upload. |
| IBM AML Transactions (Kaggle, CDLA-Sharing-1.0) | Candidate domain-shift test only, not yet run; cite arXiv 2306.16424; do not redistribute modified data. |
| AMLSim / PaySim / BankSim / SMS-phishing / voice-deepfake sets | Not used. |
| Private bank or UPI extracts | Not used. |

No third-party dataset is combined with EarlyTrace tokens. **No Kaggle** credential is read and no Kaggle upload is allowed. This prototype makes no **DPDP** compliance claim. Human actions are **record-only**; there is **no automatic** freeze, reject, reverse, or report path. A future rights decision must record licence, release, checksum, permitted use, and redistribution before any preprocessing.

## What manifests must say

Every run states synthetic status, generator, seed, split, engine, feature contract, code version, limitations, and the dependency-lock hash. The v1 runtime is `earlytrace-b0b1-heuristic-v1` / `motif.v1`, **uncalibrated**. The v2 runtime is `earlytrace-b0b1-heuristic-v2` with `b0.v2` / `motif.v2`; the 5-seed benchmark is supported multi-seed evidence, while any single-story smoke run is not. Latency numbers are unloaded in-process samples, **not a loaded service SLO**. RMSE is not a success metric here.

## v2 source, consent, and token boundary

The source allowlist is only in-process `SYNTHETIC_GENERATOR`, `SANDBOX_FIXTURE`, and `STAGING_REGISTERED_FIXTURE`. `EXTERNAL_BANK`, `BANK`, `NPCI`, `UPI_SWITCH`, `CLOUD`, and unknown values are disabled. Consent is verified server-side; invalid/missing/expired/revoked/conflicting consent returns UNKNOWN, while a verified hub outage is explicitly `LOCAL_ONLY`.

Tokens are **pseudonymous, not anonymous** if linked outside this system. HTTP, fixtures, exports, logs, and manifests contain only `tok_` live tokens or `case_` display pseudonyms. No raw account/reference, credential, exact amount, contact, message, voice, device, or IP value is in the replay fixture.
