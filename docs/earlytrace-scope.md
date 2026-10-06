# EarlyTrace scope

EarlyTrace is a synthetic prototype on the Trail hub for one workflow: a fraud-operations analyst reviewing a payment a customer is authorising to a new beneficiary, before rapid onward movement.

## In scope

- One track: AI-driven scam pattern recognition.
- One decision: allow, warn and verify, step-up, analyst review, or unknown.
- Privacy-minimised pre-authorisation events. Amounts are buckets. Parties are pseudonymous tokens.
- A deterministic motif policy (B1) beside Trail's existing six-feature heuristic (B0).
- Optional classical comparison on a synthetic, time-separated split. It is not the API runtime.
- Human-recorded review and escalation. The software does not freeze, reject, reverse, or report.

## Out of scope

- Voice, SMS, WhatsApp, call, device, or contact-list ingestion.
- A chatbot or large language model as the decision-maker.
- A temporal graph network as a required path.
- Live NPCI, UPI-switch, bank-core, ISO 20022, or cross-bank connectivity.
- A claim of DPDP compliance, production readiness, or national coverage.

## Safe degradation

If consent is missing, the event is stale, or payee age and history are both unknown, the action is `UNKNOWN`. If the hub is unavailable, the decision is marked `local_only` and uses only the caller's events. Scoring never creates an irreversible action.

## v2 trust boundary

The v2 HTTP grammar accepts only `tok_[0-9a-f]{32}` live tokens and the finite source set `SYNTHETIC_GENERATOR`, `SANDBOX_FIXTURE`, and `STAGING_REGISTERED_FIXTURE`. Bank, NPCI, UPI-switch, cloud, and unknown sources are disabled; no external connector is enabled. Duplicate or Unicode-colliding keys, forbidden aliases, raw references, unknown fields, and validation-body echoes are rejected before Pydantic construction.

Event and consent attestations use server-reconstructed allowlisted payloads, RFC-8785-style canonical UTF-8 JSON, lowercase SHA-256 digests, and unpadded base64url Ed25519 signatures. A registry key must be active, unexpired, and unrevoked at the injected verification time. The audited `earlytrace-b0b1-heuristic-v1` path remains an offline compatibility rail only; it is not a public v2 scoring contract.
