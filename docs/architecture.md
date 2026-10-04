# Architecture (Millyshree's slice)

```
Institution --local score--> signed Beacon --POST /beacons--> [verify: registry, signature, epoch, TTL, nonce, influence cap]
   --> Hub beacon store --> (Khanak) graph + ring detection --> RingRecord --> Case
   --> proposals (system-recommended, never approvals) --> human decision (RBAC, separation of duties)
   --> time-limited ActionOrder --> institution executes --> outcome / appeal --> audit (hash-chained)
```

Modules: `security/{tokens,signing,audit,rbac,ratelimit}.py`, `models/{transaction,beacon,case}.py`, `api/{institutions,complaints,beacons,cases,review,graph}.py`, `state.py`.

Endpoints: `POST /institutions/{enrol,token}`, `POST /institutions/{id}/{revoke,debits}`, `POST /complaints`, `POST /beacons`, `GET /cases`, `GET /cases/{id}`, `POST /cases/{id}/ring`, `POST /cases/{id}/proposals`, `POST /cases/{id}/proposals/{pid}/decision`, `POST /cases/{id}/orders/{oid}/{release,outcome}`, `GET /graph/{id}?view=trail|siloed&institution=X`, `GET /audit`, `GET /audit/verify`.
Auth: humans use `X-API-Key` (RBAC); institutions authenticate by Ed25519 signature + `X-Institution-Id`.
Interactive docs: `/docs` when the server is running.
