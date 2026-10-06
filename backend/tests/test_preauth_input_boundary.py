"""Finite, pre-Pydantic v2 input boundary tests."""
from __future__ import annotations

import pytest

from app.security.input_boundary import InputBoundaryError, parse_bounded_json, validate_v2_payload


def test_duplicate_and_canonical_collision_keys_are_rejected():
    with pytest.raises(InputBoundaryError):
        parse_bounded_json(b'{"event":1,"EVENT":2}')
    with pytest.raises(InputBoundaryError):
        parse_bounded_json(b'{"event":1,"e\\u0076ent":2}')


@pytest.mark.parametrize("body", [
    b'{"accountNumber":"123456789"}',
    b'{"event":{"source_token":"acct_bad"}}',
    b'{"event":{"source_token":"tok_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unexpected":1}}',
])
def test_forbidden_raw_and_unknown_values_fail_without_echo(body):
    with pytest.raises(InputBoundaryError) as exc:
        validate_v2_payload(parse_bounded_json(body))
    assert "acct_bad" not in str(exc.value)
    assert "123456789" not in str(exc.value)


def test_only_live_token_grammar_is_accepted():
    payload = {"event": {"source_token": "tok_" + "a" * 32, "payee_token": "tok_" + "b" * 32}}
    assert validate_v2_payload(payload)["event"]["source_token"].startswith("tok_")
    with pytest.raises(InputBoundaryError):
        validate_v2_payload({"event": {"source_token": "acc_" + "a" * 32}})


def test_external_sources_are_rejected():
    with pytest.raises(InputBoundaryError):
        validate_v2_payload({"event": {"event_source": "NPCI"}})
