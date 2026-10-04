# Data contracts (shared between Khanak and Millyshree)

## 1. Transaction (synthetic) — `models/transaction.py`
`transaction_id, rail, timestamp, source_institution, destination_institution, source_token, destination_token, amount_bucket, reference_token, device_token?, merchant_category?, transaction_type`

`reference_token = "tok_" + hex(Trunc128(HMAC-SHA256(K_epoch, rail || RRN || date)))` — produce it with `TokenService.reference_token(rail, reference, epoch)`. The simulator should call this, not invent random strings, so beacons, complaints and transactions all join.

## 2. Beacon — `models/beacon.py` (institution -> hub)
`token, parent_token?, epoch, rail, amount_bucket, time_bucket(5-min), edge_type(complaint_seed|derived_funds|behavioural), taint_lo_bucket?, taint_hi_bucket?, institution_id, issued_at, ttl, nonce`
Unknown fields are rejected. Amount buckets: `0_1k, 1k_10k, 10k_50k, 50k_100k, 100k_500k, 500k_plus`.
`derived_funds` beacons carry `parent_token` (token_in -> token_out). Wire format: `{beacon, signature}` posted to `POST /beacons` with header `X-Institution-Id`.

## 3. RingRecord — `models/case.py` (Khanak -> case layer)  **the integration contract**
```
RingRecord { pattern: chain|fanout|fanin|cross_bank_hop, seed_token, n_hops, institutions[],
             hops[RingHop], edges[(from_hop,to_hop)] (empty => linear), total_tainted_lo,
             confidence 0..1, reasons[], recommended_action: A0..A5 }
RingHop    { hop_index, institution, receiver_pseudonym, token, tainted_amount_lo/hi,
             minutes_since_seed, risk_score 0..1, risk_level LOW|MEDIUM|HIGH|CRITICAL,
             receiver_class ring_controlled|recruited_account|legitimate_receiver|unknown,
             p_hold_now?, reasons[] }
```
Two ways to hand it over:
1. **Push:** `POST /cases/{case_id}/ring` with a RingRecord.
2. **Hook:** implement `backend/app/detection/graph.py::build_ring_record(beacons: list[Beacon], seed_token: str) -> RingRecord | dict | None`. The hub calls it automatically after each accepted beacon on a seeded trail.

Use `TokenService.case_pseudonym(case_id, account_id)` for `receiver_pseudonym`.

## 4. Actions
A0 monitor | A1 monitoring 24h (auto) | A2 hold on lower bound (1 approver) | A3 extend to upper bound (2 approvers) | A4 full freeze (2 approvers + senior) | A5 verification outreach (1 approver). Approval defaults are placeholders to validate with compliance.
