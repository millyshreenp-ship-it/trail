"""Injected-clock attestation and consent cryptography tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.models.preauth import EventSource, PreAuthEventV2
from app.security.preauth_attestation import KeyRegistry, PreAuthAttestor


NOW = datetime(2026, 6, 1, 10, tzinfo=timezone.utc)


def event():
    return PreAuthEventV2(
        event_id="evt_attest1", occurred_at=NOW, as_of=NOW, institution_id="BANK_A",
        event_source=EventSource.SYNTHETIC_GENERATOR, rail="UPI",
        source_token="tok_" + "1" * 32, payee_token="tok_" + "2" * 32,
        amount_bucket="1k_10k", payee_age_bucket="new", session_context="ROUTINE",
        consent_scope="LOCAL_BEHAVIOUR", trace_id="trace_attest", idempotency_key="idem_attest01",
    )


def setup():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    registry = KeyRegistry(clock=lambda: NOW)
    registry.register("BANK_A", "v1", public, active_at=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(hours=1))
    return private, registry


def test_server_reconstructed_attestation_is_order_independent():
    private, registry = setup()
    attestor = PreAuthAttestor(registry, clock=lambda: NOW)
    signed = attestor.sign_event(event(), private, key_version="v1", issued_at=NOW, expires_at=NOW + timedelta(minutes=5))
    assert attestor.verify_event(event(), signed, now=NOW).ok
    changed = event().model_copy(update={"amount_bucket": "10k_50k"})
    assert not attestor.verify_event(changed, signed, now=NOW).ok


@pytest.mark.parametrize("mutation", ["signature", "institution_id", "event_digest", "expires_at"])
def test_attestation_mutations_fail(mutation):
    private, registry = setup()
    attestor = PreAuthAttestor(registry, clock=lambda: NOW)
    signed = attestor.sign_event(event(), private, key_version="v1", issued_at=NOW, expires_at=NOW + timedelta(minutes=5))
    updates = {"signature": signed.signature[:-1] + ("A" if signed.signature[-1] != "A" else "B"),
               "institution_id": "BANK_B", "event_digest": "0" * 64,
               "expires_at": NOW - timedelta(minutes=1)}
    assert not attestor.verify_event(event(), signed.model_copy(update={mutation: updates[mutation]}), now=NOW).ok


def test_key_expiry_and_revocation_use_injected_clock():
    private, registry = setup()
    attestor = PreAuthAttestor(registry, clock=lambda: NOW)
    signed = attestor.sign_event(event(), private, key_version="v1", issued_at=NOW, expires_at=NOW + timedelta(minutes=5))
    registry.revoke("BANK_A", "v1", NOW)
    assert not attestor.verify_event(event(), signed, now=NOW).ok
