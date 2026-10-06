"""Pre-Pydantic JSON boundary for the EarlyTrace v2 HTTP grammar."""
from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping
from typing import Any

MAX_BODY_BYTES = 65_536
MAX_DEPTH = 8
MAX_TOKENS = 2_000

# Versioned finite table. Values are canonicalised before this set is checked.
FORBIDDEN_KEY_ALIASES = frozenset({
    "account", "account_number", "account_no", "account_id", "acct", "acct_number",
    "iban", "pan", "aadhaar", "aadhar", "pin", "mpin", "otp", "password", "cvv",
    "phone", "phone_number", "mobile", "mobile_number", "email", "vpa", "upi_id",
    "contact", "contact_list", "contacts", "name", "customer_name",
    "sms", "message", "message_body", "whatsapp", "transcript", "audio", "audio_path",
    "voice", "recording", "device", "device_id", "device_fingerprint", "ip", "ip_address",
})

TOKEN_RE = re.compile(r"^tok_[0-9a-f]{32}$")
FORBIDDEN_VALUE_RE = re.compile(r"^(?:acct_|acc_|case_)", re.IGNORECASE)
RAW_REFERENCE_RE = re.compile(r"^[0-9]{8,20}$")


class InputBoundaryError(ValueError):
    """Safe boundary failure; callers must not include the rejected body."""


class DuplicateKeyError(InputBoundaryError):
    pass


class CanonicalKeyCollision(InputBoundaryError):
    pass


def canonical_key(key: str) -> str:
    value = unicodedata.normalize("NFKC", str(key))
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"[-\s]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.casefold().strip("_")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    seen: dict[str, str] = {}
    for raw_key, value in pairs:
        key = canonical_key(raw_key)
        if key in seen:
            raise DuplicateKeyError("duplicate or colliding JSON key")
        seen[key] = raw_key
        out[key] = value
    return out


def _scan(value: Any, *, depth: int = 0, count: list[int] | None = None, path: str = "") -> None:
    count = count if count is not None else [0]
    count[0] += 1
    if count[0] > MAX_TOKENS:
        raise InputBoundaryError("JSON token limit exceeded")
    if depth > MAX_DEPTH:
        raise InputBoundaryError("JSON depth limit exceeded")
    if isinstance(value, dict):
        for key, child in value.items():
            canonical = canonical_key(key)
            if canonical in FORBIDDEN_KEY_ALIASES:
                raise InputBoundaryError("forbidden field")
            _scan(child, depth=depth + 1, count=count, path=path)
    elif isinstance(value, list):
        for child in value:
            _scan(child, depth=depth + 1, count=count, path=path)
    elif isinstance(value, str) and FORBIDDEN_VALUE_RE.match(value):
        raise InputBoundaryError("forbidden reference")


def parse_bounded_json(body: bytes | str, *, max_bytes: int = MAX_BODY_BYTES) -> dict[str, Any]:
    raw = body.encode("utf-8") if isinstance(body, str) else body
    if len(raw) > max_bytes:
        raise InputBoundaryError("request body too large")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(InputBoundaryError("invalid number")))
    except (UnicodeDecodeError, json.JSONDecodeError, InputBoundaryError) as exc:
        if isinstance(exc, InputBoundaryError):
            raise
        raise InputBoundaryError("invalid JSON") from None
    if not isinstance(parsed, dict):
        raise InputBoundaryError("JSON object required")
    _scan(parsed)
    return parsed


def validate_v2_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate safe values before Pydantic; return a canonical-key copy."""
    data = _pairs([(str(k), v) for k, v in payload.items()])
    _scan(data)
    allowed_top = {"schema_version", "event", "attestation", "trace_id", "idempotency_key",
                   "declared_payee_age_bucket", "declared_session_context", "declared_consent_scope", "fixture_id"}
    unknown_top = set(data) - allowed_top
    if unknown_top:
        raise InputBoundaryError("unknown field")
    if "event" in data:
        if not isinstance(data["event"], dict):
            raise InputBoundaryError("event object required")
        allowed_event = {"schema_version", "event_id", "occurred_at", "institution_id",
                         "event_source", "rail", "source_token", "payee_token",
                         "amount_bucket", "payee_age_bucket", "session_context", "consent_scope", "trace_id", "idempotency_key"}
        if set(data["event"]) - allowed_event:
            raise InputBoundaryError("unknown field")
    if "attestation" in data:
        if not isinstance(data["attestation"], dict):
            raise InputBoundaryError("attestation object required")
        allowed_attestation = {"event_id", "institution_id", "event_digest", "issued_at", "expires_at",
                               "issuer_key_version", "signature"}
        if set(data["attestation"]) - allowed_attestation:
            raise InputBoundaryError("unknown field")
    if data.get("schema_version") not in (None, "earlytrace.preauth.v2"):
        # Older or future schemas are handled by the safe envelope parser.
        raise InputBoundaryError("unsupported schema")
    if "event" in data and isinstance(data["event"], dict):
        event = data["event"]
        for key in ("source_token", "payee_token"):
            if key in event and (not isinstance(event[key], str) or not TOKEN_RE.fullmatch(event[key])):
                raise InputBoundaryError("invalid live token")
        if event.get("event_source") not in (None, "SYNTHETIC_GENERATOR", "SANDBOX_FIXTURE", "STAGING_REGISTERED_FIXTURE"):
            raise InputBoundaryError("event source is not enabled")
    def reject_raw(value: Any) -> None:
        if isinstance(value, str) and RAW_REFERENCE_RE.fullmatch(value):
            raise InputBoundaryError("raw reference is not accepted")
        if isinstance(value, dict):
            for item in value.values():
                reject_raw(item)
        elif isinstance(value, list):
            for item in value:
                reject_raw(item)
    reject_raw(data)
    return data


# Compatibility names used by focused tests and future ASGI adapters.
validate_input = validate_v2_payload
scan_json = parse_bounded_json
