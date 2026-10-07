# Architecture outline — EarlyTrace

## Summary

EarlyTrace is a **synthetic-only**, advisory pre-authorisation layer. The reported engine `earlytrace-b0b1-heuristic-v2` (`b0.v2` / `motif.v2`) is a hand-built heuristic; runtime scores are **uncalibrated** risk indices (`NOT_FITTED` unless a verified calibration artifact is loaded). The frozen `earlytrace-b0b1-heuristic-v1` path is offline-regression only. No live bank/NPCI/UPI/cloud/customer integration, no neural/conformal model, **no automatic** action, **no DPDP** or **production** claim. The earlier v1 run rested on **one alert**; latency samples are unloaded in-process, **not a loaded service SLO**. External dataset **rights and checksums** are unresolved; **no Kaggle** upload. Tokens are **pseudonymous, not anonymous**.

## End-to-end flow

```text
institution event
  -> server-signed/attested identifier+digest envelope (no semantic fields on the wire)
  -> consent + history context (server-owned; event-time boundary; excludes future/equal-time)
  -> B0 six-feature adapter + B1 motif policy
  -> RiskDecision: action, uncertainty/UNKNOWN, reasons, coverage, participation
  -> analyst workspace (tenant-scoped queue, evidence graph, timeline)
  -> record-only receipt (effect=recorded_only)
  -> hash-chained PAUD audit (verified on boot)
```

**Never collected:** OTP/PIN/MPIN, exact amounts, phone/email/VPA, raw account/reference, device fingerprints, IP, audio, SMS/WhatsApp, contacts.

## Trust boundary

The public decision route is v2-only. The HTTP request is an identifier/digest envelope; semantic event fields, history, `as_of`, hub state, and participation cannot arrive on the request. The server resolves a registered event and checks its digest before scoring. `UNKNOWN` is safe behaviour for missing/invalid/expired/revoked/conflicting consent, stale/future events, unavailable/conflicting context, insufficient evidence, or unsupported schema. `LOCAL_ONLY` is derived from participation and never upgrades evidence.

## Runtime profiles

- `sandbox`: synthetic local fixtures, demo keys, in-memory storage allowed for tests, local CORS. A public-demo flag narrows exposed keys to the single analyst.
- `staging`: rehearsal only; strong secret, institution-bound hashed users, durable audit/PAUD SQLite, dependency lock, explicit non-local CORS, disabled demo/live integrations.
- `production`: intentionally refuses startup.

`/healthz` is liveness. `/readyz` checks both audit chains, configuration, storage, lock, synthetic provenance, and `live_integrations=false`. `/version` exposes only safe profile/engine/calibration/provenance state. No endpoint returns secrets or keys.

## Frontend

React/TypeScript workspace at `/workspace/`: tenant-scoped queue, evidence graph (locally bundled, no CDN), event-time timeline, understandable reasons, record-only receipts, a benchmark tab, and a Hardware tab with a 3D simulation driven by the **same signed challenge/acknowledge protocol** as the server. Committed, pending, offline-replay, and UNKNOWN request states are distinct; a committed decision is retained even if a follow-up read fails. The legacy deterministic console remains at `/console/`.

## Deployment

- Private GCP staging VM (Terraform, 10 resources, no public IP, IAP-only SSH, Secret Manager, digest-pinned Artifact Registry image), `asia-south1`, project `fablecraft-4ab6c`. `/readyz` ready.
- Public sandbox demo on Cloud Run (one instance, scale-to-zero, shared synthetic tenant, one-click login).
- AWS is a portability plan only (EC2/ECS, S3, RDS, Secrets Manager/KMS, SageMaker, Bedrock, CloudWatch). Amazon Fraud Detector is closed to new customers (Nov 2025) and is not a dependency.

## Optional, not validated (appendix)

- **ESP32** signed-challenge step-up: firmware source only, not compiled or flashed; proves physical presence, not intent.
- **Solana** Devnet audit checkpoints: payload test passes, Rust type-checks in a Linux container, not deployed; proves record integrity only.
- **AI-drafted** analyst summaries: deterministic fallback, disabled by default; drafts for human review, never a decision.

## Deliberately absent

Kafka, Neo4j, a graph database, federated learning, a required temporal graph network, live bank/NPCI/UPI connectivity, automatic freeze/reject/reverse/report, voice/audio ingestion, Kaggle publication, DPDP compliance, and a supported production deployment.
