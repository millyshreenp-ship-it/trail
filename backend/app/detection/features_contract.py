"""Canonical event-time feature contracts for EarlyTrace v2."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.detection.motifs import EventIndex, MOTIF_FEATURE_NAMES, MotifEvent, build_event_index, extract_motif_features, history_for
from app.security.canonical_json import canonical_json_bytes

B0_FEATURE_NAMES = (
    "fwd_ratio_15m", "t_fwd_median", "in_uniq_senders_1h",
    "out_fan_out_1h", "acct_age_days", "activity_jump",
)
MOTIF_V2_FEATURE_NAMES = tuple(MOTIF_FEATURE_NAMES)


def _contract_hash(name: str, names: tuple[str, ...], units: dict[str, str] | None = None) -> str:
    payload = {"name": name, "ordered_names": list(names), "value_type": "finite_float", "units": units or {}, "current_event_rule": "event_id != current.event_id and occurred_at < current.occurred_at"}
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


B0_CONTRACT = "b0.v2"
MOTIF_CONTRACT = "motif.v2"
B0_FEATURE_HASH = _contract_hash(B0_CONTRACT, B0_FEATURE_NAMES)
MOTIF_FEATURE_HASH = _contract_hash(MOTIF_CONTRACT, MOTIF_V2_FEATURE_NAMES)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("feature timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def build_event_index_v2(events, feature_as_of: datetime, visible_institutions: set[str] | None = None) -> EventIndex:
    """Build an index whose consumers must still apply ``history_for``."""
    return build_event_index(events, _utc(feature_as_of), visible_institutions=visible_institutions)


def _payee_age_days(bucket: str) -> float:
    return {"new": 0.0, "0_7d": 3.5, "7_30d": 18.5, "30_90d": 60.0, "90d_plus": 180.0, "unknown": 0.0}.get(bucket, 0.0)


@dataclass(frozen=True)
class FeatureVector:
    contract: str
    names: tuple[str, ...]
    values: tuple[float, ...]
    feature_hash: str
    feature_as_of: datetime

    def as_dict(self) -> dict[str, float]:
        return dict(zip(self.names, self.values))


def _strict_motif_features(current: Any, context: Any, feature_as_of: datetime) -> dict[str, float]:
    events = getattr(context, "events", context)
    visible = getattr(context, "visible_institutions", None)
    index = build_event_index_v2(events, feature_as_of, visible_institutions=visible)
    history = history_for(index, current)
    prior_index = EventIndex(index.as_of, list(history))
    payee = extract_motif_features(prior_index, current.payee_token, feature_as_of)
    source = extract_motif_features(prior_index, current.source_token, feature_as_of)
    features = {name: max(payee.get(name, 0.0), source.get(name, 0.0)) for name in MOTIF_V2_FEATURE_NAMES}
    # Current metadata is explicit and cannot contribute to historical counts.
    features["payee_age_new"] = 1.0 if getattr(current.payee_age_bucket, "value", current.payee_age_bucket) == "new" else 0.0
    features["urgent_context"] = 1.0 if getattr(current.session_context, "value", current.session_context) == "URGENT_SOCIAL_ENGINEERING" else 0.0
    features["new_payee_no_onward"] = 1.0 if features["payee_age_new"] and payee.get("outbound_count_24h", 0.0) == 0 else 0.0
    return {name: float(features.get(name, 0.0)) for name in MOTIF_V2_FEATURE_NAMES}


def feature_vector_for_event(current_event: Any, context: Any, feature_as_of: datetime) -> FeatureVector:
    """The sole B1/HGB/calibration/evaluation vector builder."""
    feature_as_of = _utc(feature_as_of)
    if feature_as_of != _utc(current_event.occurred_at):
        raise ValueError("feature_as_of must equal the attested subject event time")
    features = _strict_motif_features(current_event, context, feature_as_of)
    values = tuple(float(features[name]) for name in MOTIF_V2_FEATURE_NAMES)
    return FeatureVector(MOTIF_CONTRACT, MOTIF_V2_FEATURE_NAMES, values, MOTIF_FEATURE_HASH, feature_as_of)


def b0_vector_for_event(current_event: Any, context: Any, feature_as_of: datetime) -> FeatureVector:
    """Six-feature v2 B0 adapter using the same strict earlier-history rule."""
    vector = feature_vector_for_event(current_event, context, feature_as_of)
    f = vector.as_dict()
    values = (
        f["rapid_forward_ratio"], f["fwd_delay_median_min"], f["fan_in"],
        f["fan_out"], _payee_age_days(getattr(current_event.payee_age_bucket, "value", current_event.payee_age_bucket)),
        min(12.0, f["outbound_count_24h"]),
    )
    return FeatureVector(B0_CONTRACT, B0_FEATURE_NAMES, tuple(values), B0_FEATURE_HASH, vector.feature_as_of)


def b0_risk_index(vector: FeatureVector) -> float:
    if vector.contract != B0_CONTRACT or vector.names != B0_FEATURE_NAMES or vector.feature_hash != B0_FEATURE_HASH:
        raise ValueError("B0 feature contract mismatch")
    f = dict(zip(vector.names, vector.values))
    normalised = (
        min(1.0, max(0.0, f["fwd_ratio_15m"] / 1.0)),
        0.0 if f["t_fwd_median"] >= 900 else min(1.0, max(0.0, 1 - f["t_fwd_median"] / 15)),
        min(1.0, max(0.0, f["in_uniq_senders_1h"] / 8)),
        min(1.0, max(0.0, f["out_fan_out_1h"] / 6)),
        min(1.0, max(0.0, 1 - f["acct_age_days"] / 90)),
        min(1.0, max(0.0, f["activity_jump"] / 12)),
    )
    weights = (0.32, 0.18, 0.12, 0.15, 0.10, 0.13)
    return round(max(0.0, min(1.0, sum(w * x for w, x in zip(weights, normalised)))), 4)


def b1_risk_index(vector: FeatureVector) -> float:
    if vector.contract != MOTIF_CONTRACT or vector.names != MOTIF_V2_FEATURE_NAMES or vector.feature_hash != MOTIF_FEATURE_HASH:
        raise ValueError("motif feature contract mismatch")
    f = vector.as_dict()
    score = (.34 * f["rapid_forward_ratio"] + .16 * f["payee_age_new"] + .14 * f["urgent_context"] + .10 * min(1, f["fan_out"] / 4) + .06 * min(1, f["fan_in"] / 4) + .06 * f["dormant_burst"] + .06 * f["structuring"] + .04 * min(1, f["institution_changes"] / 3) + .04 * f["delayed_hop"])
    return round(max(0.0, min(1.0, score)), 4)
