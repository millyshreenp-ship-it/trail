import time
import pytest
from app.models.beacon import Beacon, SignedBeacon
from app.security.signing import BeaconVerifier, InstitutionRegistry, generate_keypair, sign_beacon
from tests.conftest import make_beacon, tok


@pytest.fixture
def setup():
    reg = InstitutionRegistry()
    priv, pub = generate_keypair(); reg.register("BANK_A", pub)
    priv2, pub2 = generate_keypair(); reg.register("BANK_B", pub2)
    return reg, priv, priv2


def v(reg, **kw):
    return BeaconVerifier(reg, **kw)


def test_valid_beacon_passes(setup, st):
    reg, pa, _ = setup
    sb = sign_beacon(make_beacon(st, "BANK_A", tok(1)), pa)
    assert v(reg).verify(sb, "BANK_A").ok


def test_tampered_beacon_rejected(setup, st):
    reg, pa, _ = setup
    sb = sign_beacon(make_beacon(st, "BANK_A", tok(1)), pa)
    forged = SignedBeacon(beacon=sb.beacon.model_copy(update={"amount_bucket": "0_1k"}), signature=sb.signature)
    assert v(reg).verify(forged, "BANK_A").reason == "BAD_SIGNATURE"


def test_signed_by_other_institution_rejected(setup, st):
    reg, pa, pb = setup
    sb = sign_beacon(make_beacon(st, "BANK_A", tok(1)), pb)  # BANK_B's key, BANK_A's name
    assert v(reg).verify(sb, "BANK_A").reason == "BAD_SIGNATURE"


def test_claimed_vs_declared_institution_mismatch(setup, st):
    reg, pa, pb = setup
    sb = sign_beacon(make_beacon(st, "BANK_A", tok(1)), pa)
    assert v(reg).verify(sb, "BANK_B").reason == "INSTITUTION_MISMATCH"


def test_unknown_and_revoked_institution(setup, st):
    reg, pa, _ = setup
    sb = sign_beacon(make_beacon(st, "BANK_A", tok(1)), pa)
    assert v(reg).verify(sb, "NOPE").reason == "UNKNOWN_OR_REVOKED_INSTITUTION"
    reg.revoke("BANK_A")
    assert v(reg).verify(sb, "BANK_A").reason == "UNKNOWN_OR_REVOKED_INSTITUTION"


def test_replay_rejected(setup, st):
    reg, pa, _ = setup
    ver = v(reg)
    sb = sign_beacon(make_beacon(st, "BANK_A", tok(1)), pa)
    assert ver.verify(sb, "BANK_A").ok
    assert ver.verify(sb, "BANK_A").reason == "REPLAY"


def test_expiry_ttl(setup, st):
    reg, pa, _ = setup
    now = [time.time()]
    ver = v(reg, clock=lambda: now[0])
    sb = sign_beacon(make_beacon(st, "BANK_A", tok(1), ttl=60, issued_at=int(now[0])), pa)
    now[0] += 61
    assert ver.verify(sb, "BANK_A").reason == "EXPIRED"


def test_future_dated_rejected(setup, st):
    reg, pa, _ = setup
    sb = sign_beacon(make_beacon(st, "BANK_A", tok(1), issued_at=int(time.time()) + 3600), pa)
    assert v(reg).verify(sb, "BANK_A").reason == "ISSUED_IN_FUTURE"


def test_stale_epoch_rejected(setup, st):
    reg, pa, _ = setup
    sb = sign_beacon(make_beacon(st, "BANK_A", tok(1), epoch="2020-01-01"), pa)
    assert v(reg).verify(sb, "BANK_A").reason == "STALE_EPOCH"


def test_influence_cap(setup, st):
    reg, pa, _ = setup
    ver = v(reg, influence_cap=3)
    results = [ver.verify(sign_beacon(make_beacon(st, "BANK_A", tok(i)), pa), "BANK_A").reason for i in range(5)]
    assert results == ["OK", "OK", "OK", "INFLUENCE_CAP_EXCEEDED", "INFLUENCE_CAP_EXCEEDED"]


def test_extra_fields_forbidden(st):
    with pytest.raises(Exception):
        Beacon(**{**make_beacon(st, "BANK_A", tok(1)).model_dump(), "account_number": "123"})
