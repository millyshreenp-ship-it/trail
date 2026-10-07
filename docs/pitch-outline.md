# Pitch outline

## One sentence

EarlyTrace is a **synthetic-only**, advisory, explainable pre-authorisation decision and review layer that scores one payment at the urgent-new-payee moment, abstains when unsure, and keeps every action **record-only** on a hash-chained audit trail.

## Evidence (synthetic, 5-seed)

Source `data/evaluation/sim2-multiseed-product-v2` (engine `earlytrace-b0b1-heuristic-v2`): seeds 7/11/23/47/89, 3,000 stories/seed, `support_gate: supported`, seed 7 has 9,536 events and a 1,872-event test window. At the 20-per-1,000 budget B0/B1/HGB tie at precision 1.0, recall 0.038 — explain this honestly as budget-limited, not a model win. Story-level means: B1 recall 0.615 (lead 73 min, false friction 0.052), HGB 0.422 (lead ~1 min), B0 0.0; event PR-AUC 0.954/0.892/0.966, all **uncalibrated**. Degradation (seed 7, B1): hub outage 0.46, partial visibility 0.587. The earlier v1 point rested on **one alert**; latency is unloaded in-process, **not a loaded service SLO**. No neural/conformal, **production**, **DPDP**, live-integration, or scientific-baseline claim.

## Problem

A customer is persuaded to pay a new beneficiary, and funds move onward before a complaint exists. An analyst needs a bounded, explainable reason to verify or review while it is still a question, not a verdict. Alerts must be few and explainable.

## What we show

The workspace scores a minimised synthetic pre-authorisation event using event-time-safe motifs, then shows source, verified consent, participation/local-only state, coverage, uncertainty/UNKNOWN, risk-index-versus-probability labels, engine/calibration IDs, expiry, and a **record-only** receipt. A live public sandbox demo lets anyone drive the queue, evidence graph, benchmark tab, and 3D hardware lab with one click.

## Positioning (designed to consume, not replace)

MuleHunter is account-level and batched; DoT FRI is mobile-number risk; RBI DPIP is national intelligence sharing. EarlyTrace is the per-event, explainable, abstaining decision layer **designed to consume** those signals. Never written as "integrated".

## Data and safety disclosure

The only approved data source is the in-repo synthetic generator. External dataset **rights and checksums** are unresolved; **no Kaggle** upload or token join. Tokens are **pseudonymous, not anonymous**. No voice/SMS/contact/device/IP/raw-account/exact-amount ingestion; no bank/NPCI/UPI-switch/cloud/customer connector. AI assistance and third-party assets are disclosed. AI-generated images are labelled "AI-generated concept render, not a photographed prototype".

## What we do not claim

- No **production**, **DPDP** compliance, national coverage, real-bank integration, or generalisation claim.
- Synthetic data we generated — descriptive, not generalisable; B1 misses ~38% of positive stories; outage degrades to ~46%.
- **No automatic** freeze, reject, reverse, accusation, police/I4C/NPCI report, or account report.
- Optional ESP32, Solana, and AI-draft prototypes are **not validated** and belong in the appendix.
- Legacy Cases is a separately labelled complaint / institution-executed workflow.
