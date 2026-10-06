"""Small, deterministic RFC-8785-style JSON boundary for EarlyTrace."""
from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any


def _normalise(value: Any) -> Any:
    if isinstance(value, Enum):
        return _normalise(value.value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, dict):
        return {str(key): _normalise(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "model_dump"):
        return _normalise(value.model_dump(mode="json"))
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Return compact, sorted UTF-8 JSON text with stable primitive handling."""
    normalised = _normalise(value)
    return json.dumps(normalised, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256_hex(value)


def normalise_unicode(value: str) -> str:
    return unicodedata.normalize("NFKC", value)
