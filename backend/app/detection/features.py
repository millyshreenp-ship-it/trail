"""Local behavioural features (Khanak Part 1 — six initial features).

Features (per account, computed from a transaction window):
  fwd_ratio_15m      – fraction of inbound value forwarded within 15 minutes
  t_fwd_median       – median minutes from inbound credit to next outbound
  in_uniq_senders_1h – unique counterparties sending into the account in 1h
  out_fan_out_1h     – unique destinations paid by the account in 1h
  acct_age_days      – days since first observed activity (proxy for tenure)
  activity_jump      – recent 1h count / median daily count (burst detector)

All pure Python; no ML framework required for the MVP feature layer.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Iterable, Sequence

from app.models.transaction import Transaction

# Canonical feature order used by the scorer
FEATURE_NAMES = (
    "fwd_ratio_15m",
    "t_fwd_median",
    "in_uniq_senders_1h",
    "out_fan_out_1h",
    "acct_age_days",
    "activity_jump",
)

# Amount-bucket midpoints (INR) for value-weighted ratios
_BUCKET_MID = {
    "0_1k": 500.0,
    "1k_10k": 5_500.0,
    "10k_50k": 30_000.0,
    "50k_100k": 75_000.0,
    "100k_500k": 300_000.0,
    "500k_plus": 750_000.0,
}


def _mid(bucket: str) -> float:
    return _BUCKET_MID.get(bucket, 10_000.0)


def _ensure_aware(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


def compute_account_features(
    transactions: Sequence[Transaction],
    account_token: str,
    *,
    as_of: datetime | None = None,
    window_hours: float = 24.0,
) -> dict[str, float]:
    """Compute the six MVP features for one account.

    Parameters
    ----------
    transactions : all known txs (any institutions); filtered to those touching account.
    account_token : source_token or destination_token to score.
    as_of : evaluation time (default = max timestamp involving the account).
    window_hours : look-back for short-term counters (default 24h; 1h slices inside).
    """
    touching = [
        t
        for t in transactions
        if t.source_token == account_token or t.destination_token == account_token
    ]
    if not touching:
        return {name: 0.0 for name in FEATURE_NAMES}

    touching = sorted(touching, key=lambda t: _ensure_aware(t.timestamp))
    if as_of is None:
        as_of = _ensure_aware(touching[-1].timestamp)
    else:
        as_of = _ensure_aware(as_of)

    first_ts = _ensure_aware(touching[0].timestamp)
    acct_age_days = max(0.0, (as_of - first_ts).total_seconds() / 86400.0)

    # Split inbound / outbound relative to this account
    inbound = [t for t in touching if t.destination_token == account_token]
    outbound = [t for t in touching if t.source_token == account_token]

    # --- fwd_ratio_15m & t_fwd_median ---------------------------------------
    forward_delays: list[float] = []
    forwarded_value = 0.0
    total_in_value = 0.0
    for inc in inbound:
        total_in_value += _mid(inc.amount_bucket)
        inc_ts = _ensure_aware(inc.timestamp)
        # next outbound after this inbound within 15 min
        for out in outbound:
            out_ts = _ensure_aware(out.timestamp)
            if out_ts < inc_ts:
                continue
            delay_min = (out_ts - inc_ts).total_seconds() / 60.0
            if delay_min <= 15.0:
                forward_delays.append(delay_min)
                forwarded_value += min(_mid(out.amount_bucket), _mid(inc.amount_bucket))
                break

    fwd_ratio_15m = (forwarded_value / total_in_value) if total_in_value > 0 else 0.0
    t_fwd_median = float(median(forward_delays)) if forward_delays else 999.0  # large = no forward

    # --- 1h windows ending at as_of ----------------------------------------
    h1 = as_of - timedelta(hours=1.0)
    in_1h = [t for t in inbound if _ensure_aware(t.timestamp) >= h1]
    out_1h = [t for t in outbound if _ensure_aware(t.timestamp) >= h1]
    in_uniq_senders_1h = float(len({t.source_token for t in in_1h}))
    out_fan_out_1h = float(len({t.destination_token for t in out_1h}))

    # --- activity_jump: recent 1h count vs median daily count --------------
    # Build daily counts over the observed life of the account
    day_counts: dict[str, int] = defaultdict(int)
    for t in touching:
        day_key = _ensure_aware(t.timestamp).date().isoformat()
        day_counts[day_key] += 1
    daily = list(day_counts.values()) or [0]
    med_daily = float(median(daily)) if daily else 0.0
    recent_1h_count = float(len(in_1h) + len(out_1h))
    # Normalise: if med_daily is 0, any activity is a jump
    if med_daily <= 0:
        activity_jump = recent_1h_count * 2.0  # strong signal for brand-new burst
    else:
        # Scale 1h rate to daily equivalent (×24) then ratio to median
        activity_jump = (recent_1h_count * 24.0) / med_daily

    return {
        "fwd_ratio_15m": round(min(1.0, max(0.0, fwd_ratio_15m)), 4),
        "t_fwd_median": round(t_fwd_median, 2),
        "in_uniq_senders_1h": in_uniq_senders_1h,
        "out_fan_out_1h": out_fan_out_1h,
        "acct_age_days": round(acct_age_days, 2),
        "activity_jump": round(activity_jump, 3),
    }


def compute_features_batch(
    transactions: Sequence[Transaction],
    accounts: Iterable[str] | None = None,
    *,
    as_of: datetime | None = None,
) -> dict[str, dict[str, float]]:
    """Compute features for many accounts. If accounts is None, score every token seen."""
    if accounts is None:
        accounts = set()
        for t in transactions:
            accounts.add(t.source_token)
            accounts.add(t.destination_token)
    return {
        acct: compute_account_features(transactions, acct, as_of=as_of)
        for acct in accounts
    }


def feature_vector(features: dict[str, float]) -> list[float]:
    """Stable ordered vector for downstream models."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]
