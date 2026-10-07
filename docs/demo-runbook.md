# Demo runbook

## Boundary

A **synthetic-only** EarlyTrace prototype. The reported engine is `earlytrace-b0b1-heuristic-v2`; the frozen `earlytrace-b0b1-heuristic-v1` path is offline-regression only. Scores are **uncalibrated** risk indices. No neural, conformal, live-integration, **production**, **DPDP**, or scientific-baseline claim is made. External dataset **rights and checksums** are unresolved and **no Kaggle** upload is allowed. Human actions are **record-only**; the system has **no automatic** freeze/reject/reverse/report. The earlier v1 operating point rested on **one alert**; latency numbers are unloaded in-process samples, **not a loaded service SLO**.

## Public sandbox demo (no login required)

**https://earlytrace-demo-749096933589.asia-south1.run.app**

- Opens the analyst workspace. The 3D hardware lab and benchmark tabs load without a login.
- Click **Connect**, then **Sandbox institution analyst** — a one-click synthetic login with no key to type.
- You land in a synthetic bank (`BANK_A`) with a live step-up decision, an evidence graph, an event-time timeline, and record-only receipts.
- Shared synthetic tenant; state resets when the instance idles. The scored fixture goes stale after ~6 hours and shows UNKNOWN; a redeploy resets it.

## Local workspace

```text
# backend
uvicorn app.main:app --app-dir backend
# frontend (dev)
cd frontend; npm run dev        # workspace at /workspace/
```

- Sandbox accounts are exposed only by `GET /meta` in the sandbox profile. In the public-demo flag only the one analyst key is exposed.
- The console calls the v2 decision and view routes, then record-only display/review/step-up/escalate and quarantined feedback routes. Any API failure returns to the labelled offline replay and does not invent a receipt. A committed decision is retained even if a follow-up read fails.
- `/healthz` is liveness. `/readyz` and `/version` expose safe operational status without secrets. `staging` is a rehearsal profile and fails closed for weak/default secrets, demo keys, memory storage, missing lock/users/paths, local or wildcard CORS, failed chains, or any live integration. The `production` profile refuses startup.

## Legacy console

`frontend/index.html` (served at `/console/`) is the earlier deterministic replay. The **Legacy Cases** panel is a complaint / institution-executed workflow, labelled separately; it is not an EarlyTrace action.

## Evaluation

```text
python research/kaggle/run.py --stories 3000 --out data/evaluation/sim2-multiseed-product-v2
```

Read the metrics file it names. Lead with story recall, lead time, and false friction, not the tied alert-budget row. Do not present synthetic figures as live-payment performance.
