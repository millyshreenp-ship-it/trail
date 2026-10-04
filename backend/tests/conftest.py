import base64, time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.beacon import Beacon, EdgeType
from app.security.signing import generate_keypair, sign_beacon
from app.state import HubState, reset_state

SECRET = b"unit-test-master-secret-0123456789"


@pytest.fixture
def st():
    return reset_state(HubState(master_secret=SECRET))


@pytest.fixture
def client(st):
    return TestClient(app)


H = lambda k: {"X-API-Key": k}
L1, L2A, L2B, SENIOR, AUDITOR, ADMIN_A = "dev-l1-key", "dev-l2a-key", "dev-l2b-key", "dev-senior-key", "dev-auditor-key", "dev-admin-a-key"


@pytest.fixture
def keys(st):
    """Enrol BANK_A..C and WALLET_W directly in the registry; return private keys."""
    out = {}
    for inst in ("BANK_A", "BANK_B", "BANK_C", "WALLET_W"):
        priv, pub = generate_keypair()
        st.registry.register(inst, pub)
        out[inst] = priv
    return out


def make_beacon(st, inst, token, parent=None, edge=EdgeType.DERIVED_FUNDS, **kw):
    now = int(time.time())
    epoch = datetime.fromtimestamp(now, tz=timezone.utc).date().isoformat()
    data = dict(token=token, parent_token=parent, epoch=epoch, rail="UPI", amount_bucket="50k_100k",
                time_bucket="10:30", edge_type=edge, institution_id=inst, issued_at=now, ttl=3600)
    data.update(kw)
    return Beacon(**data)


def tok(n):  # deterministic fake token
    return "tok_" + f"{n:032x}"
