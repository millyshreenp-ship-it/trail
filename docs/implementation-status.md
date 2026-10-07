# EarlyTrace v2 implementation status

**Status:** the v2 product build is implemented, committed, and locally verified. The analyst workspace, the comparable B0/B1/HGB research reports, the 5-seed benchmark, the GCP staging deployment, the public Cloud Run sandbox demo, and the optional (disabled-by-default) integrations are in place. All data is **synthetic**; the runtime is a hand-built heuristic with **uncalibrated** risk indices; actions are **record-only**; no **production**, **DPDP**, real-bank, neural, or scientific-win claim is made.

## What is implemented

- **Analyst workspace** — React/TypeScript at `/workspace/`: tenant-scoped queue, evidence graph (locally bundled), event-time timeline, record-only receipts, benchmark tab, and a Hardware tab with a 3D simulation driven by the same signed challenge/acknowledge protocol as the server. Request states (committed / pending / offline-replay / UNKNOWN) are distinct, and a committed decision survives a failed follow-up read.
- **Workspace API** — tenant-scoped decision queue, evidence graph, audit receipts, and review summaries, authenticated per tenant.
- **Comparable research reports** — B0/B1/HGB each report alert-budget precision/recall, story recall, lead time, false friction, innocent review, PR-AUC, UNKNOWN coverage, candidate runtime, and simulated outage diagnostics. An indexed per-account history lookup gives feature/decision parity with the full-history path at lower cost.
- **5-seed benchmark** — `data/evaluation/sim2-multiseed-product-v2`, seeds 7/11/23/47/89, 3,000 stories/seed, `support_gate: supported`.
- **Simulator** — legitimate urgent lookalikes and disguised non-urgent scams, so urgency is not a perfect label shortcut.
- **Deployment** — private GCP staging VM via Terraform (10 resources, no public IP, IAP-only SSH, Secret Manager, digest-pinned image), and a public Cloud Run sandbox demo.
- **Optional prototypes (disabled by default)** — AI-draft summaries (deterministic fallback), ESP32 signed-challenge protocol (firmware source only), Solana blinded audit checkpoints (not deployed).

## Reported metrics (synthetic, 5-seed)

Engine `earlytrace-b0b1-heuristic-v2` (`b0.v2` / `motif.v2`), source `data/evaluation/sim2-multiseed-product-v2`.

| Metric | B0 | B1 | HGB |
|---|---:|---:|---:|
| Alert-budget precision (20/1k, ~37.6 slots) | 1.0 | 1.0 | 1.0 |
| Alert-budget recall (tie — not a ranking) | 0.038 | 0.038 | 0.038 |
| Story recall (5-seed mean) | 0.0 | 0.615 | 0.422 |
| Mean lead time | — | 73 min | ~1 min |
| False friction | 0.0 | 0.052 | 0.0 |
| Event PR-AUC (uncalibrated) | 0.954 | 0.892 | 0.966 |

Degradation (seed 7, B1): hub outage 0.46, partial visibility 0.587. Latency p50 0.040 ms (B0/B1), 0.823 ms (HGB) — unloaded in-process, **not a loaded service SLO**. The frozen v1 run rested on **one alert** and is superseded.

## Claim-to-proof table

| Claim | Artifact / path | Verify with |
|---|---|---|
| Backend tests pass (218) | `backend/tests/` | `cd backend; python -m pytest -q` |
| Frontend contract tests pass (9) | `frontend/src/**/*.test.ts` | `cd frontend; npm test` |
| 5-seed benchmark, supported | `data/evaluation/sim2-multiseed-product-v2/aggregate.json` | `python research/kaggle/run.py --stories 3000 --out data/evaluation/sim2-multiseed-product-v2` |
| Workspace serves | `frontend/`, `backend/app/api/workspace.py` | `uvicorn app.main:app --app-dir backend` -> `GET /workspace/` |
| Public demo ready | Cloud Run service | `curl https://earlytrace-demo-749096933589.asia-south1.run.app/readyz` |
| Staging infra, no public IP | `deploy/gcp/main.tf` | `terraform plan` (read-only), VM `/readyz` over IAP |
| Record-only actions | `backend/app/storage/preauth.py` | receipts show `effect=recorded_only` |
| ESP32 protocol (not flashed) | `integrations/hardware/` | server challenge/ack tests |
| Solana payload (not deployed) | `integrations/solana/` | `node --test integrations/solana/protocol.test.mjs` |

## Known failures, limitations, and pending work

- **No production claim:** synthetic/local or explicitly configured staging rehearsal only. No bank/NPCI/UPI-switch/cloud/customer/voice/SMS/device/contact integration; no **DPDP** claim; **no automatic** freeze, reject, reversal, report, accusation, or enforcement.
- **No scientific-baseline win:** the alert-budget row is a three-way tie; story-level numbers are descriptive synthetic evidence. B1 misses ~38% of positive stories.
- **Data rights:** external dataset **rights and checksums** (IEEE-CIS, Elliptic, IBM AML) remain unresolved or pending. **No Kaggle** download, upload, or redistribution. Licence/checksum/redistribution review is required before any external-data work.
- **Optional prototypes not validated:** ESP32 firmware is not compiled or flashed; the Solana program is not deployed to Devnet.
- **Operational boundary:** readiness checks and local smokes are not a loaded-service benchmark. Tokens are **pseudonymous, not anonymous** if linked outside this system.

## Remaining work

1. Investigate B1's per-scenario misses, raise story recall, and improve the hub-outage case (46%).
2. Publish a story-recall-vs-alerts-per-1,000 curve to replace the tied alert-budget comparison.
3. Resolve external dataset licences/checksums, then run the IBM AML domain-shift slice with graph-motif features only, and report honestly.
4. Compile and flash the ESP32, and publish a Solana Devnet checkpoint, only if they work; otherwise keep them labelled as optional concept prototypes.
5. Run a simulated analyst-workload study (alerts per analyst-hour) for a measured before/after on alert load.
