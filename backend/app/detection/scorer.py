"""Calibrated local risk scoring with human-readable explanations (Khanak Part 1).

MVP approach: transparent weighted linear score + piecewise calibration to [0, 1],
mapped to LOW / MEDIUM / HIGH / CRITICAL. No black-box model required for the
first demo; LightGBM can replace the core later without changing the interface.

Interface
---------
    scorer = RiskScorer()
    result = scorer.score(features)          # RiskResult
    result = scorer.score_account(txs, tok)  # convenience
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence

from app.detection.features import FEATURE_NAMES, compute_account_features, compute_round_trip_ratio
from app.models.case import RiskLevel
from app.models.transaction import Transaction


@dataclass(frozen=True)
class RiskResult:
    risk_score: float  # calibrated 0–1
    risk_level: RiskLevel
    reasons: list[str] = field(default_factory=list)
    features: dict[str, float] = field(default_factory=dict)
    raw_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "reasons": list(self.reasons),
            "features": dict(self.features),
        }


# Weights tuned so a classic rapid-forward mule lands HIGH/CRITICAL and a
# quiet long-tenure account lands LOW. Sum of positive weights ≈ 1.0.
_WEIGHTS = {
    "fwd_ratio_15m": 0.32,
    "t_fwd_median": 0.18,       # inverted: lower minutes → higher risk
    "in_uniq_senders_1h": 0.12,
    "out_fan_out_1h": 0.15,
    "acct_age_days": 0.10,      # inverted: younger → higher risk
    "activity_jump": 0.13,
}

# Soft saturation points for each feature (roughly 95th pct of scam class)
_ROUND_TRIP_DISCOUNT = 0.85  # max fraction of raw risk removed when funds fully round-trip

_SAT = {
    "fwd_ratio_15m": 1.0,
    "t_fwd_median": 15.0,       # minutes; we invert below
    "in_uniq_senders_1h": 8.0,
    "out_fan_out_1h": 6.0,
    "acct_age_days": 90.0,      # days; invert
    "activity_jump": 12.0,
}


def _norm(name: str, value: float) -> float:
    """Map raw feature to [0, 1] risk contribution (higher = riskier)."""
    sat = _SAT[name]
    if name == "t_fwd_median":
        # 0 min → 1.0, ≥15 min or no-forward (999) → 0.0
        if value >= 900:
            return 0.0
        return max(0.0, min(1.0, 1.0 - (value / sat)))
    if name == "acct_age_days":
        # brand-new → 1.0, ≥90 days → 0.0
        return max(0.0, min(1.0, 1.0 - (value / sat)))
    # higher is riskier
    return max(0.0, min(1.0, value / sat))


def _calibrate(raw: float) -> float:
    """Piecewise calibration so scores are interpretable probabilities.

    Empirically places:
      quiet legit ≈ 0.05–0.20
      shopkeeper / rent ≈ 0.15–0.35
      typical mule hop ≈ 0.65–0.90
      aggressive fan-out ≈ 0.85–0.98
    """
    # logistic-ish stretch around 0.45
    x = max(0.0, min(1.0, raw))
    # mild S-curve without numpy
    stretched = x * x * (3.0 - 2.0 * x)  # smoothstep
    return round(max(0.0, min(1.0, stretched)), 4)


def _level(score: float) -> RiskLevel:
    if score >= 0.85:
        return RiskLevel.CRITICAL
    if score >= 0.60:
        return RiskLevel.HIGH
    if score >= 0.35:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _reasons(features: dict[str, float], score: float) -> list[str]:
    """Human-readable bullets matching the execution-plan style."""
    why: list[str] = []
    fr = features.get("fwd_ratio_15m", 0.0)
    if fr >= 0.5:
        pct = int(round(fr * 100))
        why.append(f"{pct}% of inbound value forwarded within 15 minutes")
    elif fr >= 0.25:
        why.append("Partial rapid forwarding of recent inbound funds")

    t_fwd = features.get("t_fwd_median", 999.0)
    if 0 < t_fwd <= 5:
        why.append(f"Median forward latency only {t_fwd:.0f} minutes")
    elif 0 < t_fwd <= 15:
        why.append(f"Median forward latency {t_fwd:.0f} minutes (under 15 min threshold)")

    fan = features.get("out_fan_out_1h", 0.0)
    if fan >= 4:
        why.append(f"High fan-out: {int(fan)} distinct beneficiaries in 1 hour")
    elif fan >= 2:
        why.append(f"Multiple new beneficiaries in the last hour ({int(fan)})")

    senders = features.get("in_uniq_senders_1h", 0.0)
    if senders >= 4:
        why.append(f"Inflow from {int(senders)} distinct senders in 1 hour")

    age = features.get("acct_age_days", 0.0)
    jump = features.get("activity_jump", 0.0)
    if age < 7 and jump >= 2:
        why.append("Previously dormant / brand-new account became highly active")
    elif age < 30 and jump >= 4:
        why.append("Young account with sharp activity jump")
    elif jump >= 8:
        why.append(f"Activity jump {jump:.1f}× above normal daily baseline")

    # Cross-institution signals are added by the graph layer (detection/graph.py).

    if not why and score >= 0.35:
        why.append("Moderate combination of velocity and counterpart diversity")
    if not why:
        why.append("No strong behavioural risk indicators")

    # Cap to a readable set
    return why[:6]


class RiskScorer:
    """Local (single-institution) risk scorer.

    Stateless and deterministic given the same features.
    """

    def __init__(self, weights: dict[str, float] | None = None):
        self.weights = dict(weights or _WEIGHTS)

    def score(self, features: dict[str, float]) -> RiskResult:
        raw = 0.0
        for name in FEATURE_NAMES:
            w = self.weights.get(name, 0.0)
            raw += w * _norm(name, float(features.get(name, 0.0)))
        # Normalise by total weight so missing weights don't deflate
        total_w = sum(self.weights.get(n, 0.0) for n in FEATURE_NAMES) or 1.0
        raw = raw / total_w
        # Refund-like behaviour: funds returned to the original sender are not mule forwarding.
        rt = float(features.get("round_trip_ratio", 0.0))
        if rt > 0.0:
            raw *= 1.0 - _ROUND_TRIP_DISCOUNT * min(1.0, rt)
        calibrated = _calibrate(raw)
        level = _level(calibrated)
        reasons = _reasons(features, calibrated)
        if rt >= 0.5:
            reasons = ["Most inbound value returned to the original sender (refund-like) — risk discounted"] + reasons
        out_features = {k: float(features.get(k, 0.0)) for k in FEATURE_NAMES}
        if "round_trip_ratio" in features:
            out_features["round_trip_ratio"] = rt
        return RiskResult(
            risk_score=calibrated,
            risk_level=level,
            reasons=reasons[:6],
            features=out_features,
            raw_score=round(raw, 4),
        )

    def score_account(
        self,
        transactions: Sequence[Transaction],
        account_token: str,
        *,
        as_of: datetime | None = None,
    ) -> RiskResult:
        feats = compute_account_features(transactions, account_token, as_of=as_of)
        feats["round_trip_ratio"] = compute_round_trip_ratio(transactions, account_token, as_of=as_of)
        return self.score(feats)

    def score_many(
        self,
        transactions: Sequence[Transaction],
        accounts: Sequence[str],
        *,
        as_of: datetime | None = None,
    ) -> dict[str, RiskResult]:
        return {
            acct: self.score_account(transactions, acct, as_of=as_of)
            for acct in accounts
        }


# Module-level default for convenience
default_scorer = RiskScorer()
