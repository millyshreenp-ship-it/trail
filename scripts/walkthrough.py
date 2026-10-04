"""Runs the end-to-end case flow against the in-process API and prints a narrative.
Usage (repo root):  PYTHONPATH=backend python scripts/walkthrough.py
Synthetic data only. Detection output is a hand-written RingRecord until detection/graph.py::build_ring_record is merged."""
import base64, json, time
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.models.beacon import Beacon, EdgeType
from app.security.signing import generate_keypair, sign_beacon
from app.state import HubState, reset_state
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

st = reset_state(HubState(master_secret=b"demo-master-secret-0123456789ab"))
c = TestClient(app)
H = lambda k: {"X-API-Key": k}
say = lambda s: print(f"\n== {s}")

say("0. Institutions enrol their public keys (BANK_A via API; others directly for brevity)")
keys = {}
for inst in ("BANK_A", "BANK_B", "WALLET_W", "BANK_C"):
    priv, pub = generate_keypair(); keys[inst] = priv
    if inst == "BANK_A":
        print(c.post("/institutions/enrol", json={"institution_id": inst, "public_key_b64": base64.b64encode(pub).decode()},
                     headers=H("dev-admin-a-key")).json())
    else:
        st.registry.register(inst, pub)

say("1-2. Victim complaint, corroborated against Bank A's own debit record")
ts = datetime.now(timezone.utc).replace(microsecond=0)
tk = st.tokens.reference_token("UPI", "412345678901", ts.date().isoformat())
c.post("/institutions/BANK_A/debits", json={"token": tk, "amount_bucket": "50k_100k"}, headers=H("dev-admin-a-key"))
r = c.post("/complaints", json={"victim_institution": "BANK_A", "rail": "UPI", "reference": "412345678901",
                                "amount": 78000, "timestamp": ts.isoformat()}, headers=H("dev-l1-key")).json()
print(r); cid, seed = r["case_id"], r["seed_token"]

say("3. Signed beacons trace the money Bank A -> Bank B -> Wallet -> Bank C")
prev = seed
for i, inst in enumerate(["BANK_B", "WALLET_W", "BANK_C"], 1):
    t = "tok_" + f"{i:032x}"
    b = Beacon(token=t, parent_token=prev, epoch=ts.date().isoformat(), rail="UPI", amount_bucket="50k_100k",
               time_bucket="10:30", edge_type=EdgeType.DERIVED_FUNDS, institution_id=inst, issued_at=int(time.time()))
    print(inst, c.post("/beacons", json=sign_beacon(b, keys[inst]).model_dump(mode="json"),
                       headers={"X-Institution-Id": inst}).json()); prev = t
sb = sign_beacon(Beacon(token="tok_" + f"{1:032x}", epoch=ts.date().isoformat(), rail="UPI", amount_bucket="50k_100k",
                        time_bucket="10:30", edge_type=EdgeType.BEHAVIOURAL, institution_id="BANK_B", issued_at=int(time.time())), keys["BANK_B"])
c.post("/beacons", json=sb.model_dump(mode="json"), headers={"X-Institution-Id": "BANK_B"})
print("replay of same beacon ->", c.post("/beacons", json=sb.model_dump(mode="json"), headers={"X-Institution-Id": "BANK_B"}).json())
print("two-key rule satisfied (complaint + behaviour):", st.can_share_onward(seed))

say("4-7. Detection engine output (SIMULATED RingRecord) attached to the case")
def hop(i, inst, risk, lvl, cls, lo, hi, m, why):
    return dict(hop_index=i, institution=inst, receiver_pseudonym=st.tokens.case_pseudonym(cid, f"acct-{i}"), token="tok_" + f"{100+i:032x}",
                tainted_amount_lo=lo, tainted_amount_hi=hi, minutes_since_seed=m, risk_score=risk, risk_level=lvl, receiver_class=cls, reasons=why)
ring = {"pattern": "cross_bank_hop", "seed_token": seed, "n_hops": 4, "institutions": ["BANK_A", "BANK_B", "WALLET_W", "BANK_C"],
        "hops": [hop(0, "BANK_A", .81, "HIGH", "ring_controlled", 78000, 78000, 4, ["82% forwarded within 15 min"]),
                 hop(1, "BANK_B", .55, "MEDIUM", "legitimate_receiver", 30000, 40000, 9, ["Regular merchant settlement pattern"]),
                 hop(2, "WALLET_W", .88, "HIGH", "ring_controlled", 40000, 48000, 14, ["Dormant account burst"]),
                 hop(3, "BANK_C", .95, "CRITICAL", "ring_controlled", 38000, 44000, 22, ["Cash-out mix"])],
        "total_tainted_lo": 78000, "confidence": .91, "reasons": ["Cross-institution movement"], "recommended_action": "A5"}
print(json.dumps(c.post(f"/cases/{cid}/ring", json=ring, headers=H("dev-l1-key")).json(), indent=2, default=str))
print("Bank A alone sees", len(c.get(f"/graph/{cid}?view=siloed&institution=BANK_A", headers=H("dev-l1-key")).json()["nodes"]), "of 4 hops")

say("8-11. Human review: verification for the merchant, time-limited hold for the high-confidence receiver")
props = {p["hop_index"]: p for p in c.get(f"/cases/{cid}", headers=H("dev-l2a-key")).json()["case"]["proposals"]}
for hopi in (1, 3):
    out = c.post(f"/cases/{cid}/proposals/{props[hopi]['proposal_id']}/decision", json={"decision": "approve", "note": "reviewed"},
                 headers=H("dev-l2a-key")).json()
    o = out["order"]
    print(f"hop {hopi}: {o['action']} at {o['institution']} | reason {o['reason_code']} | audit {o['audit_id']} | expires {o['expires_at']} | {o['execution']}")
print("\naudit chain:", c.get("/audit/verify", headers=H("dev-auditor-key")).json())
