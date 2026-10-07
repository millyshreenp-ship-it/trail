"""Receiver classification for ring hops (Khanak).

Classes (models.case.ReceiverClass):
  ring_controlled  – structural mule / cash-out behaviour
  recruited_account – intermediate, possibly unwitting
  legitimate_receiver – merchant / long-tenure settlement pattern
  unknown
"""
from __future__ import annotations

from typing import Any

from app.models.case import ReceiverClass, RiskLevel


def classify_receiver(
    *,
    hop_index: int,
    n_hops: int,
    risk_score: float,
    risk_level: RiskLevel,
    out_degree: int,
    in_degree: int,
    institution: str,
    is_terminal: bool,
    pattern: str,
    reasons: list[str] | None = None,
    features: dict[str, float] | None = None,
) -> ReceiverClass:
    """Heuristic classifier — explainable, no black-box.

    Rules (first match wins, ordered by specificity):
    1. Terminal cash-out with high risk → ring_controlled
    2. High fan-out origin → ring_controlled
    3. Mid-path, moderate risk → legitimate only with evidence (tenure >= 30d and no rapid
       forwarding) when features are available; otherwise recruited
    4. High risk anywhere in coordinated pattern → ring_controlled
    5. Low risk mid-path → legitimate_receiver
    """
    reasons = reasons or []

    def has_legit_evidence() -> bool:
        """Positive evidence of a genuine receiver: established account that does NOT rapidly forward.

        When transaction features are unavailable (beacon-only path) we cannot check, so we
        fall back to the position-based heuristic (returns True).
        """
        if features is None:
            return True
        return features.get("acct_age_days", 0.0) >= 30.0 and features.get("fwd_ratio_15m", 0.0) < 0.5

    reason_blob = " ".join(reasons).lower()

    # Explicit merchant / settlement language from local scorer
    if any(k in reason_blob for k in ("merchant", "settlement", "regular", "tenure")):
        if risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM):
            return ReceiverClass.LEGITIMATE

    if is_terminal and risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        return ReceiverClass.RING_CONTROLLED

    if out_degree >= 3 and risk_score >= 0.5:
        return ReceiverClass.RING_CONTROLLED

    if pattern == "fanin" and hop_index == 0 and in_degree >= 3:
        return ReceiverClass.RING_CONTROLLED

    if risk_level == RiskLevel.CRITICAL:
        return ReceiverClass.RING_CONTROLLED

    if risk_level == RiskLevel.HIGH:
        # Mid-chain high-risk is usually ring-controlled; first hop after seed can be recruited
        if hop_index == 0 and n_hops > 2:
            return ReceiverClass.RECRUITED
        return ReceiverClass.RING_CONTROLLED

    if risk_level == RiskLevel.MEDIUM:
        # Classic: intermediate bank that looks like a real merchant/settlement
        if 0 < hop_index < n_hops - 1 and out_degree <= 2 and has_legit_evidence():
            return ReceiverClass.LEGITIMATE
        return ReceiverClass.RECRUITED

    # LOW
    if 0 < hop_index < n_hops - 1:
        return ReceiverClass.LEGITIMATE if has_legit_evidence() else ReceiverClass.RECRUITED
    return ReceiverClass.UNKNOWN


def structural_risk_from_graph(
    *,
    out_degree: int,
    in_degree: int,
    hop_index: int,
    n_hops: int,
    n_institutions: int,
    minutes_since_seed: float,
    is_terminal: bool,
) -> tuple[float, list[str]]:
    """When no transaction-level features exist (beacon-only path), score from structure."""
    score = 0.15  # base
    why: list[str] = []

    if n_institutions >= 3:
        score += 0.18
        why.append("Cross-institution movement")
    elif n_institutions >= 2:
        score += 0.10
        why.append("Multi-institution trail")

    if n_hops >= 4:
        score += 0.12
        why.append(f"Deep trail ({n_hops} hops)")
    elif n_hops >= 3:
        score += 0.08

    if minutes_since_seed > 0 and minutes_since_seed <= 30 and hop_index > 0:
        score += 0.15
        why.append(f"Rapid hop: {minutes_since_seed:.0f} min from seed")
    elif minutes_since_seed <= 60 and hop_index > 0:
        score += 0.08
        why.append(f"Forwarded within {minutes_since_seed:.0f} min of seed")

    if out_degree >= 3:
        score += 0.20
        why.append(f"High fan-out ({out_degree} destinations)")
    elif out_degree >= 2:
        score += 0.08
        why.append("Multiple beneficiaries")

    if in_degree >= 3:
        score += 0.12
        why.append(f"Fan-in collector ({in_degree} senders)")

    if is_terminal and n_hops >= 3:
        score += 0.12
        why.append("Terminal cash-out position on multi-hop trail")

    score = max(0.0, min(0.98, score))
    if not why:
        why.append("Limited structural signal")
    return round(score, 4), why
