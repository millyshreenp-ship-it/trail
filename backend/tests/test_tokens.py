import hashlib
import pytest
from app.security.tokens import TokenService, previous_epoch

S = b"unit-test-master-secret-0123456789"


def test_deterministic_and_format():
    t = TokenService(S)
    a = t.reference_token("UPI", "123456789012", "2026-10-04")
    assert a == t.reference_token("UPI", "123456789012", "2026-10-04")
    assert a.startswith("tok_") and len(a) == 4 + 32


def test_not_a_plain_hash():
    t = TokenService(S)
    plain = hashlib.sha256(b"UPI123456789012").hexdigest()[:32]
    assert plain not in t.reference_token("UPI", "123456789012", "2026-10-04")


def test_different_secret_different_token():
    assert TokenService(S).reference_token("UPI", "1", "2026-10-04") != \
        TokenService(b"another-secret-0123456789abcdef").reference_token("UPI", "1", "2026-10-04")


def test_epoch_rotation_changes_token_but_prev_epoch_still_matches():
    t = TokenService(S)
    yesterday = t.reference_token("UPI", "123456789012", "2026-10-03")
    today = t.reference_token("UPI", "123456789012", "2026-10-04")
    assert yesterday != today
    assert t.matches(yesterday, "UPI", "123456789012", "2026-10-04")   # previous epoch accepted
    assert not t.matches(t.reference_token("UPI", "123456789012", "2026-10-01"), "UPI", "123456789012", "2026-10-04")


def test_rail_is_part_of_the_token():
    t = TokenService(S)
    assert t.reference_token("UPI", "1", "2026-10-04") != t.reference_token("IMPS", "1", "2026-10-04")


def test_case_pseudonyms_are_case_scoped():
    t = TokenService(S)
    assert t.case_pseudonym("TRAIL-1", "acct9") != t.case_pseudonym("TRAIL-2", "acct9")
    assert t.case_pseudonym("TRAIL-1", "acct9") == t.case_pseudonym("TRAIL-1", "acct9")


def test_weak_or_missing_secret_rejected(monkeypatch):
    monkeypatch.delenv("TRAIL_MASTER_SECRET", raising=False)
    with pytest.raises(ValueError):
        TokenService()
    with pytest.raises(ValueError):
        TokenService(b"short")
