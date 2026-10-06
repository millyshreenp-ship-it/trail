# Trail Hub

Cross-institution scam-trail intelligence with human-controlled response. Institutions score behaviour locally and send signed, minimised **beacons**; the hub links them into a **ring case**; analysts review; approvers authorise **time-limited orders**. Nothing is ever frozen automatically.

```
Institution → local score → signed beacon → verify (registry · signature · epoch · TTL · nonce · influence cap)
  → hub → graph + ring detection → case → proposals → human decision (RBAC, separation of duties)
  → time-limited order → institution executes → outcome / appeal → hash-chained audit
```

## Quick start
```bash
make install
export TRAIL_MASTER_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))")
make test                 # 40 tests
make sandbox              # seeds one synthetic case → http://localhost:8000/console/
docker compose up --build # containerised, durable audit volume
```
API reference: `/docs` (disabled when `TRAIL_ENV=production`). Health: `/healthz`, `/readyz` (verifies audit chain).

## Capabilities
| Area | Implementation |
|---|---|
| Keyed reference tokens, daily epoch rotation | `security/tokens.py` |
| Beacon schema (strict, no hidden fields) | `models/beacon.py` |
| Ed25519 sign/verify, replay, TTL, institution auth, influence cap, revocation | `security/signing.py` |
| Case, complaint, graph APIs | `api/` |
| Proposals → approvals → time-limited orders, two-key rule, lien caps | `api/review.py` |
| RBAC + separation of duties, hashed API keys | `security/rbac.py` |
| Durable hash-chained audit (fsync, verified on boot) | `security/audit.py` |
| Investigator console (queue, trail/siloed graph, explainability, decisions, audit) | `frontend/` |
| Config validation, request IDs, security headers, CI, Docker | `config.py`, `main.py`, `.github/`, `Dockerfile` |

## Detection & evaluation (Khanak workstream)
```
make evaluate     # generate the synthetic corpus, run siloed-vs-Trail, write docs/evaluation.md
```
- `backend/app/simulator/` — 5,000+ legitimate and 500+ suspicious transactions: chain, fan-out, fan-in, cross-bank hop, plus legitimate lookalikes (shared devices, student rent, shopkeeper, refunds, gig worker, high-volume business). `generate_dataset()` also returns `ring_meta` ground truth.
- `backend/app/detection/` — features, explainable scorer, lineage graph, ring detection, receiver classification, `evaluation.py` (B0 vs Trail).
- `notebooks/` — 01 feature analysis, 02 rule-vs-LightGBM comparison, 03 graph + evaluation (`pip install jupyter matplotlib pandas scikit-learn lightgbm` to run).
- Results: [`docs/evaluation.md`](docs/evaluation.md). Synthetic data only; numbers describe the simulator, not production.

## Configuration
See `.env.example`. With `TRAIL_ENV=production` the service refuses to start without a strong master secret, hashed user keys (`TRAIL_USERS_JSON`), a durable audit path and non-localhost CORS origins; sandbox accounts and API docs are disabled.

## Integration contract (detection engine)
`RingRecord` in `models/case.py` — see `docs/data-contract.md`. Either `POST /cases/{id}/ring`, or implement `detection/graph.py::build_ring_record(beacons, seed_token)`; the hub calls it after each accepted beacon on a seeded trail.

## Security posture
Read `docs/threat-model.md` before deploying. Key limits: software-held keys (no HSM/KMS), TLS/mTLS expected at the ingress, case and beacon stores are in-memory (audit log is durable), no legal/compliance claim is made, and approval defaults need compliance validation. Data in this repository is synthetic.
