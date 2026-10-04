"""End-to-end case flow, driven entirely through the HTTP API."""
from datetime import datetime, timedelta, timezone

import pytest
from app.models.beacon import EdgeType
from app.security.signing import sign_beacon
from tests.conftest import (ADMIN_A, AUDITOR, H, L1, L2A, L2B, SENIOR, make_beacon, tok)

REF, AMOUNT = "412345678901", 78_000
TS = datetime.now(timezone.utc).replace(microsecond=0)


def ring_payload(seed):
    def hop(i, inst, risk, level, cls, lo, hi, mins, reasons):
        return dict(hop_index=i, institution=inst, receiver_pseudonym=f"acc_{i:02d}", token=tok(100 + i),
                    tainted_amount_lo=lo, tainted_amount_hi=hi, minutes_since_seed=mins, risk_score=risk,
                    risk_level=level, receiver_class=cls, reasons=reasons)
    return {"pattern": "cross_bank_hop", "seed_token": seed, "n_hops": 4,
            "institutions": ["BANK_A", "BANK_B", "WALLET_W", "BANK_C"],
            "hops": [hop(0, "BANK_A", .81, "HIGH", "ring_controlled", 78000, 78000, 4, ["82% forwarded within 15 min"]),
                     hop(1, "BANK_B", .55, "MEDIUM", "legitimate_receiver", 30000, 40000, 9, ["Regular merchant settlement pattern"]),
                     hop(2, "WALLET_W", .88, "HIGH", "ring_controlled", 40000, 48000, 14, ["Dormant account burst"]),
                     hop(3, "BANK_C", .95, "CRITICAL", "ring_controlled", 38000, 44000, 22, ["Cash-out mix", "Similar pattern in other cases"])],
            "total_tainted_lo": 78000, "confidence": 0.91,
            "reasons": ["Cross-institution movement", "Multiple new beneficiaries"],
            "recommended_action": "A5"}


@pytest.fixture
def seeded(client, st, keys):
    token = st.tokens.reference_token("UPI", REF, TS.date().isoformat())
    r = client.post("/institutions/BANK_A/debits", json={"token": token, "amount_bucket": "50k_100k"}, headers=H(ADMIN_A))
    assert r.status_code == 200
    body = {"victim_institution": "BANK_A", "rail": "UPI", "reference": REF, "amount": AMOUNT, "timestamp": TS.isoformat()}
    r = client.post("/complaints", json=body, headers=H(L1))
    assert r.status_code == 201, r.text
    return r.json(), body, keys


def send(client, st, keys, inst, token, parent=None, edge=EdgeType.DERIVED_FUNDS):
    sb = sign_beacon(make_beacon(st, inst, token, parent, edge), keys[inst])
    return client.post("/beacons", json=sb.model_dump(mode="json"), headers={"X-Institution-Id": inst})


def test_complaint_corroboration_and_dedup(client, seeded):
    first, body, _ = seeded
    assert first["corroborated"] and first["case_id"].startswith("TRAIL-")
    dup = client.post("/complaints", json=body, headers=H(L1)).json()
    assert dup["duplicate"] and dup["case_id"] == first["case_id"]


def test_uncorroborated_complaint_rejected(client, st, keys):
    body = {"victim_institution": "BANK_A", "rail": "UPI", "reference": "999999999999", "amount": 5000, "timestamp": TS.isoformat()}
    r = client.post("/complaints", json=body, headers=H(L1))
    assert r.status_code == 422 and r.json()["detail"]["reason_code"] == "RC06_INSUFFICIENT_CORROBORATION"


def test_complaint_needs_authentication(client, st):
    assert client.post("/complaints", json={}).status_code == 401
    assert client.post("/complaints", json={}, headers=H(AUDITOR)).status_code == 403


def test_beacon_api_rejects_replay_and_bad_sender(client, st, keys, seeded):
    seed = seeded[0]["seed_token"]
    sb = sign_beacon(make_beacon(st, "BANK_B", tok(1), seed), keys["BANK_B"])
    p = sb.model_dump(mode="json")
    assert client.post("/beacons", json=p, headers={"X-Institution-Id": "BANK_B"}).status_code == 202
    assert client.post("/beacons", json=p, headers={"X-Institution-Id": "BANK_B"}).status_code == 409  # replay
    assert client.post("/beacons", json=p, headers={"X-Institution-Id": "BANK_C"}).status_code == 403  # mismatch
    st.registry.revoke("BANK_B")
    sb2 = sign_beacon(make_beacon(st, "BANK_B", tok(2), seed), keys["BANK_B"])
    assert client.post("/beacons", json=sb2.model_dump(mode="json"), headers={"X-Institution-Id": "BANK_B"}).status_code == 401


def test_two_key_rule_onward_sharing(client, st, keys, seeded):
    seed = seeded[0]["seed_token"]
    assert not st.can_share_onward(seed)                    # complaint only: one key
    assert send(client, st, keys, "BANK_B", tok(1), seed).status_code == 202
    assert not st.can_share_onward(seed)                    # derived-funds edge is not independent evidence
    # behavioural beacon on an UNRELATED token must not count toward this trail
    assert send(client, st, keys, "BANK_C", tok(99), None, EdgeType.BEHAVIOURAL).status_code == 202
    assert not st.can_share_onward(seed)
    # behavioural beacon on a token that descends from the seed: complaint + behaviour => second key
    assert send(client, st, keys, "BANK_B", tok(1), None, EdgeType.BEHAVIOURAL).status_code == 202
    assert st.can_share_onward(seed)


def test_full_north_star_flow(client, st, keys, seeded):
    info, _, _ = seeded
    cid, seed = info["case_id"], info["seed_token"]
    # trace across institutions
    prev = seed
    for i, inst in enumerate(["BANK_B", "WALLET_W", "BANK_C"], start=1):
        assert send(client, st, keys, inst, tok(i), prev).status_code == 202
        prev = tok(i)
    # detection engine hands the ring to the case layer
    r = client.post(f"/cases/{cid}/ring", json=ring_payload(seed), headers=H(L1))
    assert r.status_code == 200
    card = r.json()
    assert card["n_hops"] == 4 and card["likely_legitimate"] == 1 and card["high_risk_receivers"] == 3
    # queue shows it; auditor can read but not act
    assert client.get("/cases", headers=H(AUDITOR)).json()[0]["case_id"] == cid
    detail = client.get(f"/cases/{cid}", headers=H(L2A)).json()
    props = {p["hop_index"]: p for p in detail["case"]["proposals"]}
    assert props[1]["action"] == "A5" and props[1]["reason_code"] == "RC03_LIKELY_LEGIT"   # verify, not freeze
    assert props[3]["action"] == "A2" and props[3]["amount_cap"] == 38000                    # capped hold
    # siloed toggle: Bank A alone sees one hop
    silo = client.get(f"/graph/{cid}?view=siloed&institution=BANK_A", headers=H(L1)).json()
    full = client.get(f"/graph/{cid}", headers=H(L1)).json()
    assert len(silo["nodes"]) == 1 and len(full["nodes"]) == 4 and silo["hidden_hops"] == 3
    # L1 analyst cannot approve; auditor cannot approve
    pid_hold, pid_verify = props[3]["proposal_id"], props[1]["proposal_id"]
    assert client.post(f"/cases/{cid}/proposals/{pid_hold}/decision", json={"decision": "approve"}, headers=H(L1)).status_code == 403
    assert client.post(f"/cases/{cid}/proposals/{pid_hold}/decision", json={"decision": "approve"}, headers=H(AUDITOR)).status_code == 403
    # human approves hold -> time-limited order with audit id, reason code, expiry
    r = client.post(f"/cases/{cid}/proposals/{pid_hold}/decision", json={"decision": "approve", "note": "traced"}, headers=H(L2A))
    out = r.json()
    assert r.status_code == 200 and out["proposal_state"] == "APPROVED"
    assert out["audit_id"].startswith("AUD-") and out["reason_code"] == "RC02_RING_STRUCTURE"
    order = out["order"]
    assert order["execution"] == "PENDING_INSTITUTION_EXECUTION" and order["institution"] == "BANK_C"
    issued = datetime.fromisoformat(order["issued_at"]); exp = datetime.fromisoformat(order["expires_at"])
    assert exp - issued == timedelta(hours=24)
    # merchant gets verification outreach
    r = client.post(f"/cases/{cid}/proposals/{pid_verify}/decision", json={"decision": "approve"}, headers=H(L2B))
    assert r.json()["order"]["action"] == "A5"
    # institution reports outcome; wrong institution cannot
    oid = order["order_id"]
    assert client.post(f"/cases/{cid}/orders/{oid}/outcome", json={"held_amount": 38000, "final_label": "confirmed_mule"}, headers=H(ADMIN_A)).status_code == 403
    # lien auto-expires
    st.now = lambda: datetime.now(timezone.utc) + timedelta(hours=25)
    d = client.get(f"/cases/{cid}", headers=H(L2A)).json()
    assert [o["status"] for o in d["case"]["orders"] if o["order_id"] == oid] == ["EXPIRED"]
    # audit chain intact; auditor can read
    v = client.get("/audit/verify", headers=H(AUDITOR)).json()
    assert v["chain_intact"] and v["entries"] > 10
    assert client.get("/audit/verify", headers=H(L1)).status_code == 403


def _case_with_ring(client, st, keys, seeded):
    info = seeded[0]; cid, seed = info["case_id"], info["seed_token"]
    client.post(f"/cases/{cid}/ring", json=ring_payload(seed), headers=H(L1))
    return cid


def propose(client, cid, **kw):
    body = dict(hop_index=3, action="A2", reason_code="RC01_TRACED_PASSTHROUGH",
                rationale="High-confidence receiver at hop 3", amount_cap=38000)
    body.update(kw)
    return client.post(f"/cases/{cid}/proposals", json=body, headers=H(L1))


def test_holds_blocked_on_likely_legitimate_receiver(client, st, keys, seeded):
    cid = _case_with_ring(client, st, keys, seeded)
    r = propose(client, cid, hop_index=1, amount_cap=30000)
    assert r.status_code == 422 and "A5" in r.json()["detail"]


def test_lien_cap_cannot_exceed_traced_bound(client, st, keys, seeded):
    cid = _case_with_ring(client, st, keys, seeded)
    assert propose(client, cid, amount_cap=50000).status_code == 422
    assert propose(client, cid, amount_cap=None).status_code == 422
    assert propose(client, cid, duration_hours=999).status_code == 422


def test_a3_needs_two_distinct_approvers_and_proposer_cannot_self_approve(client, st, keys, seeded):
    cid = _case_with_ring(client, st, keys, seeded)
    pid = propose(client, cid, action="A3", amount_cap=44000).json()["proposal"]["proposal_id"]
    d = lambda key: client.post(f"/cases/{cid}/proposals/{pid}/decision", json={"decision": "approve"}, headers=H(key))
    assert d(L2A).json()["proposal_state"] == "PENDING"
    assert d(L2A).status_code == 409                       # same approver twice
    assert d(L2B).json()["proposal_state"] == "APPROVED"   # second distinct approver


def test_a4_requires_senior_signoff(client, st, keys, seeded):
    cid = _case_with_ring(client, st, keys, seeded)
    pid = propose(client, cid, action="A4", amount_cap=None, rationale="Rare full freeze, confirmed ring").json()["proposal"]["proposal_id"]
    d = lambda key: client.post(f"/cases/{cid}/proposals/{pid}/decision", json={"decision": "approve"}, headers=H(key))
    assert d(L2A).json()["proposal_state"] == "PENDING"
    assert d(L2B).json()["proposal_state"] == "PENDING"    # two approvers but no senior yet
    assert d(SENIOR).json()["proposal_state"] == "APPROVED"


def test_reject_and_escalate(client, st, keys, seeded):
    cid = _case_with_ring(client, st, keys, seeded)
    pid = propose(client, cid).json()["proposal"]["proposal_id"]
    r = client.post(f"/cases/{cid}/proposals/{pid}/decision", json={"decision": "reject", "note": "insufficient"}, headers=H(L2A))
    assert r.json()["proposal_state"] == "REJECTED"
    assert client.post(f"/cases/{cid}/proposals/{pid}/decision", json={"decision": "approve"}, headers=H(L2B)).status_code == 409
    pid2 = propose(client, cid, hop_index=2, amount_cap=40000).json()["proposal"]["proposal_id"]
    r = client.post(f"/cases/{cid}/proposals/{pid2}/decision", json={"decision": "escalate"}, headers=H(L2A))
    assert r.json()["case_status"] == "ESCALATED"


def test_a1_monitoring_is_auto_but_never_a_hold(client, st, keys, seeded):
    cid = _case_with_ring(client, st, keys, seeded)
    r = propose(client, cid, action="A1", amount_cap=None, reason_code="RC01_TRACED_PASSTHROUGH")
    assert r.json()["auto_approved"] and r.json()["order"]["action"] == "A1"
    # no code path auto-issues A2+ : a hold stays pending until a human approves
    r = propose(client, cid, action="A2")
    assert r.json()["auto_approved"] is False


def test_outcome_and_appeal_by_executing_institution(client, st, keys, seeded):
    cid = _case_with_ring(client, st, keys, seeded)
    pid = propose(client, cid, hop_index=0, amount_cap=78000).json()["proposal"]["proposal_id"]
    order = client.post(f"/cases/{cid}/proposals/{pid}/decision", json={"decision": "approve"}, headers=H(L2A)).json()["order"]
    r = client.post(f"/cases/{cid}/orders/{order['order_id']}/outcome",
                    json={"held_amount": 78000, "appealed": True, "final_label": "legitimate"}, headers=H(ADMIN_A))
    assert r.status_code == 200
    d = client.get(f"/cases/{cid}", headers=H(L2A)).json()
    assert d["case"]["status"] == "UNDER_REVIEW" and d["case"]["orders"][0]["status"] == "RELEASED"


def test_token_gateway_is_rate_limited(client, st):
    codes = [client.post("/institutions/token", json={"rail": "UPI", "reference": str(i), "date": "2026-10-04"},
                         headers=H(ADMIN_A)).status_code for i in range(35)]
    assert codes[:30] == [200] * 30 and 429 in codes[30:]
