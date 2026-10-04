"""Seeds a sandbox hub with one synthetic case (no decisions made) and serves API + console.
Usage (repo root):  PYTHONPATH=backend python scripts/seed_sandbox.py  ->  http://localhost:8000/console/"""
import base64, time
from datetime import datetime, timezone

import uvicorn
from fastapi.testclient import TestClient

from app.main import app
from app.models.beacon import Beacon, EdgeType
from app.security.signing import generate_keypair, sign_beacon
from app.state import HubState, reset_state

st = reset_state(HubState(master_secret=b"demo-master-secret-0123456789ab"))
c, H = TestClient(app), (lambda k: {"X-API-Key": k})
keys = {}
for inst in ("BANK_A", "BANK_B", "WALLET_W", "BANK_C"):
    keys[inst], pub = generate_keypair(); st.registry.register(inst, pub)
ts = datetime.now(timezone.utc).replace(microsecond=0)
tk = st.tokens.reference_token("UPI", "412345678901", ts.date().isoformat())
c.post("/institutions/BANK_A/debits", json={"token": tk, "amount_bucket": "50k_100k"}, headers=H("dev-admin-a-key"))
r = c.post("/complaints", json={"victim_institution": "BANK_A", "rail": "UPI", "reference": "412345678901",
                                "amount": 78000, "timestamp": ts.isoformat()}, headers=H("dev-l1-key")).json()
cid, seed, prev = r["case_id"], r["seed_token"], r["seed_token"]

def beacon(tok, inst, edge, parent=None):
    b = Beacon(token=tok, parent_token=parent, epoch=ts.date().isoformat(), rail="UPI", amount_bucket="50k_100k",
               time_bucket="10:30", edge_type=edge, institution_id=inst, issued_at=int(time.time()))
    c.post("/beacons", json=sign_beacon(b, keys[inst]).model_dump(mode="json"), headers={"X-Institution-Id": inst})
for i, inst in enumerate(("BANK_B", "WALLET_W", "BANK_C"), 1):
    t = "tok_" + f"{i:032x}"; beacon(t, inst, EdgeType.DERIVED_FUNDS, prev); prev = t
beacon("tok_" + f"{1:032x}", "BANK_B", EdgeType.BEHAVIOURAL)

def hop(i, inst, risk, lvl, cls, lo, hi, m, why):
    return dict(hop_index=i, institution=inst, receiver_pseudonym=st.tokens.case_pseudonym(cid, f"acct-{i}"),
                token="tok_" + f"{100+i:032x}", tainted_amount_lo=lo, tainted_amount_hi=hi, minutes_since_seed=m,
                risk_score=risk, risk_level=lvl, receiver_class=cls, reasons=why)
# SIMULATED detection output until Khanak's detection/graph.py::build_ring_record exists
ring = {"pattern": "cross_bank_hop", "seed_token": seed, "n_hops": 4, "institutions": ["BANK_A", "BANK_B", "WALLET_W", "BANK_C"],
        "hops": [hop(0, "BANK_A", .81, "HIGH", "ring_controlled", 78000, 78000, 4, ["82% forwarded within 15 min", "Previously dormant account became active"]),
                 hop(1, "BANK_B", .55, "MEDIUM", "legitimate_receiver", 30000, 40000, 9, ["Regular merchant settlement pattern", "Long account tenure"]),
                 hop(2, "WALLET_W", .88, "HIGH", "ring_controlled", 40000, 48000, 14, ["Dormant account burst", "Multiple new beneficiaries"]),
                 hop(3, "BANK_C", .95, "CRITICAL", "ring_controlled", 38000, 44000, 22, ["Cash-out mix (ATM + new-payee P2P)", "Similar pattern in other synthetic cases"])],
        "total_tainted_lo": 78000, "confidence": .91, "reasons": ["Cross-institution movement", "Complaint + behaviour evidence"], "recommended_action": "A5"}
c.post(f"/cases/{cid}/ring", json=ring, headers=H("dev-l1-key"))
print(f"Seeded {cid}. Console: http://localhost:8000/console/  (sandbox, no decisions yet)")
uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
