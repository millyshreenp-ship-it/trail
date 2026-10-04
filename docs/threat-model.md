# Trail threat model

> Synthetic data only. No compliance claim is made; legal review is required before any real deployment.
> Hand-written crypto here is not audited cryptography: production needs KMS/HSM, mTLS, an audited PSI/OPRF library.

## Assets
Reference tokens, beacons, the case graph, the watchlist (cases/receivers), analyst decisions, the audit log, institution keys.

## Trust zones
1. **Institution** (local scoring, raw data never leaves)
2. **Hub** (sees tokens + bucketed features only)
3. **Review** (human analysts/approvers, RBAC + audit)

## Threats, mitigations, and where they live

| # | Threat | Mitigation | Implemented in | Tested in |
|---|--------|-----------|----------------|-----------|
| T1 | Fake complaint to freeze a rival's account | Complaint must match the victim bank's own debit record; dedup; two-key rule for holds; lien capped to traced bound; auto-expiry; audit | `api/complaints.py`, `api/review.py` | `test_uncorroborated_complaint_rejected`, `test_lien_cap_cannot_exceed_traced_bound`, `test_full_north_star_flow` |
| T2 | Malicious / compromised institution injects beacons | Ed25519-signed beacons, per-institution influence cap, revocation, `extra=forbid` schema (no hidden fields) | `security/signing.py`, `models/beacon.py` | `test_signed_by_other_institution_rejected`, `test_influence_cap`, `test_unknown_and_revoked_institution`, `test_extra_fields_forbidden` |
| T3 | Replay / tampering | Nonce cache, signed `issued_at` + TTL, epoch window, canonical-JSON signature, hash-chained audit | `security/signing.py`, `security/audit.py` | `test_replay_rejected`, `test_expiry_ttl`, `test_future_dated_rejected`, `test_stale_epoch_rejected`, `test_tampered_beacon_rejected`, `test_chain_intact_then_tamper_detected` |
| T4 | Token reversal / brute force of the 12-digit RRN | Keyed HMAC-SHA256 (not a plain hash), daily rotating epoch keys derived from a master secret, token gateway rate-limited (it is otherwise a brute-force oracle) | `security/tokens.py`, `api/institutions.py` | `test_not_a_plain_hash`, `test_epoch_rotation_...`, `test_token_gateway_is_rate_limited` |
| T5 | Hub compromise | Hub holds tokens and bucketed features only; case-scoped account pseudonyms so one person cannot be followed across cases | `models/beacon.py`, `security/tokens.py::case_pseudonym` | `test_case_pseudonyms_are_case_scoped` |
| T6 | Analyst misuse / insider | RBAC (L1, L2, senior, auditor, institution admin), separation of duties (proposer != approver, approver counts once), multi-approver for A3/A4, every step audited, denied access also audited | `security/rbac.py`, `api/review.py` | `test_rbac_matrix`, `test_a3_needs_two_...`, `test_a4_requires_senior_signoff` |
| T7 | Mule herders probing "is my account flagged?" | No per-account verdict endpoint; institution admins have no case-read permission; token gateway rate limit | `security/rbac.py`, `api/institutions.py` | `test_rbac_matrix`, `test_token_gateway_is_rate_limited` |
| T8 | Automatic or over-broad freezing (collateral harm) | **No endpoint freezes anything.** Approved actions become time-limited orders that the institution executes. A1 monitoring is the only auto path. Holds blocked on likely-legitimate receivers (A5 instead). | `api/review.py`, `models/case.py::APPROVAL_POLICY` | `test_a1_monitoring_is_auto_but_never_a_hold`, `test_holds_blocked_on_likely_legitimate_receiver` |
| T9 | Watchlist leak | RBAC on all case endpoints; (production: watermarked exports, short retention) | `api/deps.py` | `test_complaint_needs_authentication` |
| T10 | Model evasion | Owned by detection workstream: adaptive-adversary evaluation, challenger models | (Khanak) | n/a |

## Safety invariant
`AI detects -> AI ranks -> human reviews -> human approves -> time-limited action -> appeal/outcome -> feedback`.
The system never freezes an account automatically.

## Known gaps
- Transport: no mTLS termination in the app (terminate TLS/mTLS at the ingress) (signatures cover integrity/authenticity, not confidentiality).
- Keys: master secret and institution keys are in process memory / env, not a KMS/HSM. Sandbox API keys exist only when `TRAIL_ENV=sandbox`; production loads sha256-hashed keys from `TRAIL_USERS_JSON`.
- Storage: the audit log is durable (fsync JSONL, verified on boot) but not externally anchored; cases and beacons are in-memory and are lost on restart (Postgres is the next step).
- Hub sees plaintext RRN once at complaint intake/token gateway (OPRF would remove this).
- Influence cap is a simple count limiter, not a trust-weighted model; two-institution corroboration for large rings is not yet enforced.
- Ring records carry numeric synthetic rupee amounts; production should bucket them.
- Jitter on probing responses and canary tokens are not implemented.
