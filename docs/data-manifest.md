# Data manifest

## What this repository generates

`scenario_preauth_mule_network` and `generate_preauth_corpus` build synthetic payment events inside this process. The generator version is `earlytrace-sim-1`.

Labels are the role planted by the story script (`social_engineering_preauth`, `mule_forward`, or `legitimate_lookalike`). They are not the output of `RiskScorer` or `score_pre_auth`.

Each run manifest records generator version, scenario name, seed, event count, the label rule, split boundaries, `data_status: synthetic`, licence, provenance, and code version.

## Licence decision

| Source | Decision |
|---|---|
| Trail synthetic EarlyTrace generator | Use. Created in this repository. Not real UPI or bank data. |
| IEEE-CIS Fraud Detection | Not downloaded. Card-not-present data, different domain, competition terms not accepted here. |
| Elliptic | Not downloaded. Bitcoin graph, not Indian payments. |
| AMLSim / AML-Data | Not downloaded. |
| Fraud Detection Handbook simulator | Not downloaded. |
| DGraph, PaySim, BankSim, SMS/phishing feeds | Not used. |
| Voice and deepfake datasets | Not used. |
| Private bank or UPI extracts | Not used. |
| Unverified sets named FinFraud-UPI-Synthetic or SCS-PhoneScam | Not used. No licence was established. |

No third-party dataset is combined with Trail tokens.

## What a manifest must say

Data are synthetic. The split name and seed are explicit. The engine version is `earlytrace-b0b1-heuristic-v1` unless a later local run records a different offline comparison.

## v2 provenance and token boundary

The v2 source allowlist is limited to in-process `SYNTHETIC_GENERATOR`, `SANDBOX_FIXTURE`, and `STAGING_REGISTERED_FIXTURE` records. `EXTERNAL_BANK`, `BANK`, `NPCI`, `UPI_SWITCH`, `CLOUD`, and unknown source values are rejected. No live bank, switch, cloud, Kaggle, or customer-data connector is part of this repository.

Internal fixture references may cross the trust boundary only through `TrustedReferenceAdapter`, which immediately produces a case-separated HMAC token. HTTP, fixtures, exports, logs, and manifests contain only `tok_` live tokens or `case_` display pseudonyms; legacy `acc_` values remain isolated compatibility data and are never accepted by the v2 input grammar. Event/consent signatures bind server-reconstructed safe envelopes, not caller-supplied signed payload text.
