# EarlyTrace scope

## What it is

EarlyTrace is a **synthetic-only** pre-authorisation prototype for one analyst workflow: score an urgent payment to a new beneficiary before rapid onward movement. The runtime engine `earlytrace-b0b1-heuristic-v2` (`b0.v2` / `motif.v2`) is a hand-built heuristic policy; runtime scores are **uncalibrated** risk indices, not probabilities. The frozen `earlytrace-b0b1-heuristic-v1` path remains only for offline v1 evaluator compatibility.

All reported numbers come from the synthetic 5-seed benchmark (`data/evaluation/sim2-multiseed-product-v2`, seeds 7/11/23/47/89, 3,000 stories/seed). They are descriptive synthetic evidence, not generalisation, production, or scientific-baseline results. The earlier v1 operating point rested on **one alert** and was not a stable estimate; latency figures are unloaded in-process samples, **not a loaded service SLO**.

## In scope

- One track: AI-driven scam pattern recognition (Track 2).
- One advisory decision: allow, warn and verify, step-up, analyst review, or UNKNOWN.
- Privacy-minimised synthetic events with bucketed amounts and pseudonymous tokens.
- Deterministic B0/B1 policy with server-owned v2 event/consent context.
- A tenant-scoped analyst workspace (queue, evidence graph, event-time timeline, record-only receipts, benchmark + hardware tabs), PAUD storage, readiness checks, and human-recorded review/escalation.
- Private GCP staging and a public sandbox demo on Cloud Run.

## Data, consent, and source boundary

Only the in-repo synthetic generator and registered sandbox/staging fixtures are allowed. `live_integrations=false`; there is no live bank, NPCI, UPI-switch, customer database, cloud, or cross-bank connector. Consent outcome, source, participation, evidence coverage, and the event-time/future-event boundary are server-owned. Missing, invalid, expired, revoked, or conflicting consent and insufficient evidence produce UNKNOWN; a hub outage may produce verified LOCAL_ONLY with a step-up ceiling, never stronger evidence.

Tokens are **pseudonymous, not anonymous** if linked outside this system. No voice/audio, SMS/WhatsApp, transcript, contact list, phone/email/VPA, raw account/reference, exact amount, OTP/PIN/MPIN, device fingerprint, or IP data is accepted, stored, logged, or exported. External dataset **rights and checksums** (IEEE-CIS, Elliptic, and others) are unresolved; **no Kaggle** download, upload, redistribution, or token join is allowed.

## Safe actions and out of scope

Human actions are **record-only** (`DISPLAY`, `REVIEW`, `STEP_UP`, `ESCALATE`) with PAUD audit receipts and `effect=recorded_only`. EarlyTrace **has no automatic** freeze, reject, reverse, accusation, hold, or police/I4C/NPCI/account report. Legacy Cases remains a separately labelled complaint / institution-executed workflow.

Out of scope: voice/SMS/WhatsApp/device/contact ingestion, a chatbot/LLM decision-maker, a required temporal graph network, live integrations, automatic action, Kaggle publication, **DPDP** compliance, **production** readiness, and national/generalisation claims. The ESP32, Solana, and AI-draft prototypes are optional and not validated. Work is AI-assisted and uses disclosed third-party libraries/assets.

## v2 trust and operational status

The public HTTP route is v2-only; the audited v1 path remains offline evaluator compatibility. Calibration is `NOT_FITTED` unless a matching verified artifact exists. Profiles are `sandbox`, `staging`, and the intentionally non-deployable `production` (refuses startup). `/healthz` is liveness; `/readyz` checks safe local/staging readiness and both audit chains; `/version` emits no secrets or keys.
