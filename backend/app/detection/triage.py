"""Ring triage, recommended actions, and siloed-vs-Trail evaluation (Khanak).

Evaluation metrics (execution plan §6.6):
  - time from complaint to ring identification
  - precision / recall at fixed analyst budget
  - innocent-lien rate
  - harm-minutes (proxy)
  - duplicate-alert ratio
  - performance with partial bank participation
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from app.models.case import ActionCode, ReceiverClass, RiskLevel, RingHop, RingRecord


def recommend_action(ring: RingRecord) -> ActionCode:
    """Case-level recommended action from hop mix (never auto-executed)."""
    classes = [h.receiver_class for h in ring.hops]
    levels = [h.risk_level for h in ring.hops]

    if any(c == ReceiverClass.LEGITIMATE for c in classes) and any(
        lv in (RiskLevel.HIGH, RiskLevel.CRITICAL) for lv in levels
    ):
        # Mixed: verify the legit-looking one; holds still available per-hop via proposals
        return ActionCode.A5

    if any(lv == RiskLevel.CRITICAL for lv in levels):
        return ActionCode.A2

    if any(lv == RiskLevel.HIGH for lv in levels):
        return ActionCode.A2

    if any(c == ReceiverClass.RECRUITED for c in classes):
        return ActionCode.A5

    if any(lv == RiskLevel.MEDIUM for lv in levels):
        return ActionCode.A1

    return ActionCode.A0


def ring_reasons(pattern: str, hops: Sequence[RingHop], institutions: Sequence[str]) -> list[str]:
    why: list[str] = []
    if len(institutions) >= 2:
        why.append("Cross-institution movement")
    if pattern == "cross_bank_hop":
        why.append("Cross-bank hop pattern (bank → bank → wallet/bank)")
    elif pattern == "chain":
        why.append("Linear multi-hop fund chain")
    elif pattern == "fanout":
        why.append("Fan-out dispersal to multiple beneficiaries")
    elif pattern == "fanin":
        why.append("Fan-in collection into a single controller")
    high = sum(1 for h in hops if h.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL))
    if high:
        why.append(f"{high} high-risk receiver(s) on the trail")
    legit = sum(1 for h in hops if h.receiver_class == ReceiverClass.LEGITIMATE)
    if legit:
        why.append(f"{legit} likely-legitimate receiver(s) — prefer verification over freeze")
    if not why:
        why.append("Coordinated pattern detected across available beacons")
    return why[:6]


# ----- Evaluation: siloed baseline (B0) vs Trail -----------------------------

@dataclass
class EvalCase:
    """One labelled evaluation unit."""
    case_id: str
    true_ring_accounts: set[str]
    true_innocent_accounts: set[str] = field(default_factory=set)
    # What each bank sees in isolation (account tokens visible to that institution)
    siloed_alerts: dict[str, set[str]] = field(default_factory=dict)
    # What Trail's cross-institution graph flagged
    trail_alerts: set[str] = field(default_factory=set)
    complaint_to_ring_minutes_siloed: float | None = None
    complaint_to_ring_minutes_trail: float | None = None
    # Partial participation: which institutions actually shared beacons
    participating_institutions: set[str] = field(default_factory=set)


@dataclass
class EvalMetrics:
    precision_siloed: float
    recall_siloed: float
    precision_trail: float
    recall_trail: float
    innocent_lien_rate_siloed: float
    innocent_lien_rate_trail: float
    median_time_to_ring_siloed: float | None
    median_time_to_ring_trail: float | None
    duplicate_alert_ratio_siloed: float
    harm_minutes_siloed: float
    harm_minutes_trail: float
    partial_participation_recall: dict[str, float]  # k institutions -> recall
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "precision_siloed": self.precision_siloed,
            "recall_siloed": self.recall_siloed,
            "precision_trail": self.precision_trail,
            "recall_trail": self.recall_trail,
            "innocent_lien_rate_siloed": self.innocent_lien_rate_siloed,
            "innocent_lien_rate_trail": self.innocent_lien_rate_trail,
            "median_time_to_ring_siloed": self.median_time_to_ring_siloed,
            "median_time_to_ring_trail": self.median_time_to_ring_trail,
            "duplicate_alert_ratio_siloed": self.duplicate_alert_ratio_siloed,
            "harm_minutes_siloed": self.harm_minutes_siloed,
            "harm_minutes_trail": self.harm_minutes_trail,
            "partial_participation_recall": self.partial_participation_recall,
            "notes": list(self.notes),
        }


def _pr(predicted: set[str], truth: set[str]) -> tuple[float, float]:
    if not predicted:
        return 0.0, 0.0
    tp = len(predicted & truth)
    prec = tp / len(predicted) if predicted else 0.0
    rec = tp / len(truth) if truth else 0.0
    return prec, rec


def evaluate_siloed_vs_trail(cases: Sequence[EvalCase]) -> EvalMetrics:
    """Aggregate B0 (per-bank union of alerts) vs Trail cross-institution alerts."""
    if not cases:
        return EvalMetrics(
            0, 0, 0, 0, 0, 0, None, None, 0, 0, 0, {},
            notes=["no evaluation cases"],
        )

    # Micro-averaged precision/recall
    sil_pred: set[str] = set()
    trail_pred: set[str] = set()
    truth: set[str] = set()
    innocent: set[str] = set()
    sil_times: list[float] = []
    trail_times: list[float] = []
    dup_numer = 0
    dup_denom = 0

    for c in cases:
        truth |= c.true_ring_accounts
        innocent |= c.true_innocent_accounts
        # B0: union of per-institution alerts
        union: set[str] = set()
        for inst, alerts in c.siloed_alerts.items():
            union |= alerts
            dup_numer += len(alerts)
        dup_denom += len(union) or 1
        sil_pred |= union
        trail_pred |= c.trail_alerts
        if c.complaint_to_ring_minutes_siloed is not None:
            sil_times.append(c.complaint_to_ring_minutes_siloed)
        if c.complaint_to_ring_minutes_trail is not None:
            trail_times.append(c.complaint_to_ring_minutes_trail)

    p_s, r_s = _pr(sil_pred, truth)
    p_t, r_t = _pr(trail_pred, truth)

    def innocent_rate(pred: set[str]) -> float:
        if not pred:
            return 0.0
        return len(pred & innocent) / len(pred)

    # Harm-minutes proxy: time-to-detect * missed mules (higher is worse)
    missed_s = len(truth - sil_pred)
    missed_t = len(truth - trail_pred)
    med_s = sorted(sil_times)[len(sil_times) // 2] if sil_times else None
    med_t = sorted(trail_times)[len(trail_times) // 2] if trail_times else None
    harm_s = (med_s or 60.0) * max(1, missed_s)
    harm_t = (med_t or 15.0) * max(1, missed_t)

    # Partial participation: recall when only k institutions share
    partial: dict[str, float] = {}
    for k in (1, 2, 3):
        hits = 0
        total = 0
        for c in cases:
            if not c.true_ring_accounts:
                continue
            total += 1
            # approximate: if ≥k institutions participated and trail found any true positive
            if len(c.participating_institutions) >= k and (c.trail_alerts & c.true_ring_accounts):
                hits += 1
        partial[f"k>={k}"] = (hits / total) if total else 0.0

    return EvalMetrics(
        precision_siloed=round(p_s, 4),
        recall_siloed=round(r_s, 4),
        precision_trail=round(p_t, 4),
        recall_trail=round(r_t, 4),
        innocent_lien_rate_siloed=round(innocent_rate(sil_pred), 4),
        innocent_lien_rate_trail=round(innocent_rate(trail_pred), 4),
        median_time_to_ring_siloed=med_s,
        median_time_to_ring_trail=med_t,
        duplicate_alert_ratio_siloed=round(dup_numer / dup_denom, 4) if dup_denom else 0.0,
        harm_minutes_siloed=round(harm_s, 2),
        harm_minutes_trail=round(harm_t, 2),
        partial_participation_recall=partial,
        notes=[
            "B0 = union of per-institution local alerts",
            "Trail = cross-institution graph ring detection",
            "innocent_lien_rate = fraction of alerts on known-innocent accounts",
            "harm_minutes ≈ median_time_to_ring × missed_ring_accounts",
        ],
    )


def demo_eval_from_rings(
    trail_rings: Sequence[RingRecord],
    *,
    labels: dict[str, str] | None = None,
) -> EvalMetrics:
    """Convenience: build EvalCases from RingRecords + optional account labels.

    labels maps account/token → 'mule'|'scam_ring'|'legit'|...
    Siloed baseline is approximated by splitting hops per institution.
    """
    labels = labels or {}
    cases: list[EvalCase] = []
    for i, ring in enumerate(trail_rings):
        true_ring = {
            h.token for h in ring.hops
            if labels.get(h.token, "mule") in ("mule", "scam_ring")
            or h.receiver_class.value in ("ring_controlled", "recruited_account")
        }
        true_innocent = {
            h.token for h in ring.hops
            if labels.get(h.token) == "legit" or h.receiver_class == ReceiverClass.LEGITIMATE
        }
        siloed: dict[str, set[str]] = {}
        for h in ring.hops:
            # Siloed: each bank only alerts on HIGH+ at its own hop
            if h.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                siloed.setdefault(h.institution, set()).add(h.token)
        trail_alerts = {h.token for h in ring.hops if h.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)}
        cases.append(
            EvalCase(
                case_id=f"eval-{i}",
                true_ring_accounts=true_ring or {h.token for h in ring.hops},
                true_innocent_accounts=true_innocent,
                siloed_alerts=siloed,
                trail_alerts=trail_alerts,
                complaint_to_ring_minutes_siloed=max((h.minutes_since_seed for h in ring.hops), default=60),
                complaint_to_ring_minutes_trail=min((h.minutes_since_seed for h in ring.hops if h.hop_index > 0), default=15),
                participating_institutions=set(ring.institutions),
            )
        )
    return evaluate_siloed_vs_trail(cases)
