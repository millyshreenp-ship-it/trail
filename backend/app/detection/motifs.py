"""Event-time motif features for EarlyTrace.

Every function takes an explicit as_of and ignores events after that instant.
Features use amount buckets, not exact amounts, and pseudonymous tokens only.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import median

MOTIF_FEATURE_NAMES = (
    "payee_age_new",
    "urgent_context",
    "inbound_count_1h",
    "outbound_count_1h",
    "inbound_count_24h",
    "outbound_count_24h",
    "fwd_delay_median_min",
    "rapid_forward_ratio",
    "fan_out",
    "fan_in",
    "fan_out_concentration",
    "fan_in_concentration",
    "distinct_counterparties",
    "dormant_burst",
    "institution_changes",
    "rail_changes",
    "delayed_hop",
    "delayed_hop_gap_min",
    "structuring",
    "merchant_fanin",
    "recurring_pair",
    "household_like",
    "refund_like",
    "new_payee_no_onward",
    "evidence_coverage",
    "participation_ratio",
    "freshness_seconds",
    "expired_fraction",
)

_BUCKET_MID = {
    "0_1k": 500.0,
    "1k_10k": 5_500.0,
    "10k_50k": 30_000.0,
    "50k_100k": 75_000.0,
    "100k_500k": 300_000.0,
    "500k_plus": 750_000.0,
}
_SMALL_BUCKETS = {"0_1k", "1k_10k"}


def _aware(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _mid(bucket: str) -> float:
    return _BUCKET_MID.get(bucket, 10_000.0)


@dataclass(frozen=True)
class MotifEvent:
    event_id: str
    occurred_at: datetime
    institution_id: str
    rail: str
    source_token: str
    payee_token: str
    amount_bucket: str
    payee_age_bucket: str
    session_context: str
    consent_scope: str = "LOCAL_BEHAVIOUR"


@dataclass
class EventIndex:
    as_of: datetime
    events: list[MotifEvent]


def _as_motif(event: object) -> MotifEvent:
    if isinstance(event, MotifEvent):
        return event
    return MotifEvent(
        event_id=event.event_id,
        occurred_at=_aware(event.occurred_at),
        institution_id=event.institution_id,
        rail=str(event.rail),
        source_token=event.source_token,
        payee_token=event.payee_token,
        amount_bucket=event.amount_bucket,
        payee_age_bucket=str(getattr(event.payee_age_bucket, "value", event.payee_age_bucket)),
        session_context=str(getattr(event.session_context, "value", event.session_context)),
        consent_scope=str(getattr(event.consent_scope, "value", event.consent_scope)),
    )


def build_event_index(events, as_of: datetime, visible_institutions: set[str] | None = None) -> EventIndex:
    """Index events that occurred at or before as_of. Future events are dropped."""
    as_of = _aware(as_of)
    kept: list[MotifEvent] = []
    for raw in events:
        ev = _as_motif(raw)
        ev = MotifEvent(
            event_id=ev.event_id,
            occurred_at=_aware(ev.occurred_at),
            institution_id=ev.institution_id,
            rail=ev.rail,
            source_token=ev.source_token,
            payee_token=ev.payee_token,
            amount_bucket=ev.amount_bucket,
            payee_age_bucket=ev.payee_age_bucket,
            session_context=ev.session_context,
            consent_scope=ev.consent_scope,
        )
        if ev.occurred_at > as_of:
            continue
        if visible_institutions is not None and ev.institution_id not in visible_institutions:
            continue
        kept.append(ev)
    kept.sort(key=lambda e: (e.occurred_at, e.event_id))
    return EventIndex(as_of=as_of, events=kept)


def history_for(index: EventIndex, current) -> tuple[MotifEvent, ...]:
    """Strict pre-authorisation history: no current/equal/post-event rows."""
    current_time = _aware(current.occurred_at)
    return tuple(e for e in index.events if e.event_id != current.event_id and _aware(e.occurred_at) < current_time)


def _zeros() -> dict[str, float]:
    return {name: 0.0 for name in MOTIF_FEATURE_NAMES}


def extract_motif_features(
    index: EventIndex,
    subject_token: str,
    as_of: datetime,
    *,
    expected_institutions: int = 1,
    evidence_ttl_s: float = 6 * 3600,
) -> dict[str, float]:
    """Motifs for one token using only events at or before as_of."""
    as_of = _aware(as_of)
    events = [e for e in index.events if e.occurred_at <= as_of]
    touching = [e for e in events if e.source_token == subject_token or e.payee_token == subject_token]
    feats = _zeros()
    if not touching:
        feats["evidence_coverage"] = 0.0
        feats["freshness_seconds"] = 1e9
        feats["expired_fraction"] = 1.0
        feats["participation_ratio"] = 0.0
        return feats

    h1 = as_of - timedelta(hours=1)
    h24 = as_of - timedelta(hours=24)
    inbound = [e for e in touching if e.payee_token == subject_token]
    outbound = [e for e in touching if e.source_token == subject_token]
    in_1h = [e for e in inbound if e.occurred_at >= h1]
    out_1h = [e for e in outbound if e.occurred_at >= h1]
    in_24 = [e for e in inbound if e.occurred_at >= h24]
    out_24 = [e for e in outbound if e.occurred_at >= h24]

    feats["inbound_count_1h"] = float(len(in_1h))
    feats["outbound_count_1h"] = float(len(out_1h))
    feats["inbound_count_24h"] = float(len(in_24))
    feats["outbound_count_24h"] = float(len(out_24))

    delays: list[float] = []
    rapid_delays: list[float] = []
    forwarded = 0.0
    total_in = 0.0
    for inc in inbound:
        total_in += _mid(inc.amount_bucket)
        for out in outbound:
            if out.occurred_at < inc.occurred_at:
                continue
            delay = (out.occurred_at - inc.occurred_at).total_seconds() / 60.0
            delays.append(delay)
            if delay <= 15.0:
                rapid_delays.append(delay)
                forwarded += min(_mid(out.amount_bucket), _mid(inc.amount_bucket))
            break
    feats["rapid_forward_ratio"] = round(forwarded / total_in, 4) if total_in else 0.0
    feats["fwd_delay_median_min"] = float(median(delays)) if delays else 0.0
    long_delays = [d for d in delays if 120.0 <= d <= 18 * 60]
    feats["delayed_hop"] = 1.0 if long_delays else 0.0
    feats["delayed_hop_gap_min"] = float(median(long_delays)) if long_delays else 0.0

    out_payees = [e.payee_token for e in out_1h]
    in_sources = [e.source_token for e in in_1h]
    feats["fan_out"] = float(len(set(out_payees)))
    feats["fan_in"] = float(len(set(in_sources)))
    feats["fan_out_concentration"] = (max(out_payees.count(p) for p in set(out_payees)) / len(out_payees)) if out_payees else 0.0
    feats["fan_in_concentration"] = (max(in_sources.count(p) for p in set(in_sources)) / len(in_sources)) if in_sources else 0.0

    parties = {e.source_token for e in touching} | {e.payee_token for e in touching}
    parties.discard(subject_token)
    feats["distinct_counterparties"] = float(len(parties))

    if len(touching) >= 2:
        gap = (touching[-1].occurred_at - touching[-2].occurred_at).total_seconds()
        recent = len(in_1h) + len(out_1h)
        # Dormant if the previous gap before the latest burst exceeds 7 days.
        if len(touching) >= 3:
            prior_gap = (touching[-2].occurred_at - touching[0].occurred_at).total_seconds()
        else:
            prior_gap = gap
        feats["dormant_burst"] = 1.0 if prior_gap >= 7 * 86400 and recent >= 3 else 0.0

    inst_changes = 0
    rail_changes = 0
    last_i, last_r = touching[0].institution_id, touching[0].rail
    for e in touching[1:]:
        if e.institution_id != last_i:
            inst_changes += 1
            last_i = e.institution_id
        if e.rail != last_r:
            rail_changes += 1
            last_r = e.rail
    feats["institution_changes"] = float(inst_changes)
    feats["rail_changes"] = float(rail_changes)

    if len(out_1h) >= 3 and len({e.amount_bucket for e in out_1h}) == 1:
        feats["structuring"] = 1.0
    elif len(outbound) >= 3:
        window = as_of - timedelta(hours=2)
        recent_out = [e for e in outbound if e.occurred_at >= window]
        if len(recent_out) >= 3 and len({e.amount_bucket for e in recent_out}) == 1:
            feats["structuring"] = 1.0

    merchant_in = [e for e in inbound if e.session_context == "MERCHANT_CHECKOUT"]
    small_in = [e for e in merchant_in if e.amount_bucket in _SMALL_BUCKETS]
    feats["merchant_fanin"] = 1.0 if len(small_in) >= 5 and feats["rapid_forward_ratio"] < 0.2 else 0.0

    pair_counts: dict[tuple[str, str], list[datetime]] = {}
    for e in touching:
        pair_counts.setdefault((e.source_token, e.payee_token), []).append(e.occurred_at)
    recurring = False
    for times in pair_counts.values():
        if len(times) < 3:
            continue
        times = sorted(times)
        gaps = [(times[i] - times[i - 1]).total_seconds() for i in range(1, len(times))]
        if gaps and median(gaps) >= 20 * 86400 and feats["rapid_forward_ratio"] < 0.2:
            recurring = True
    feats["recurring_pair"] = 1.0 if recurring else 0.0

    in_sources_24 = {e.source_token for e in in_24}
    out_payees_24 = {e.payee_token for e in out_24}
    small_share = sum(1 for e in touching if e.amount_bucket in _SMALL_BUCKETS) / len(touching)
    feats["household_like"] = 1.0 if (
        len(in_sources_24) >= 2 and len(out_payees_24) <= 1 and feats["rapid_forward_ratio"] < 0.2
        and small_share >= 0.7 and feats["merchant_fanin"] == 0.0
    ) else 0.0

    refund = False
    for e in outbound:
        for inc in inbound:
            if inc.source_token == e.payee_token and inc.payee_token == e.source_token:
                dt = abs((e.occurred_at - inc.occurred_at).total_seconds())
                if dt <= 7 * 86400 and inc.amount_bucket == e.amount_bucket:
                    refund = True
    feats["refund_like"] = 1.0 if refund and feats["fan_out"] <= 1 and feats["rapid_forward_ratio"] < 0.2 else 0.0

    latest = touching[-1]
    feats["payee_age_new"] = 1.0 if latest.payee_age_bucket == "new" else 0.0
    feats["urgent_context"] = 1.0 if latest.session_context == "URGENT_SOCIAL_ENGINEERING" else 0.0
    feats["new_payee_no_onward"] = 1.0 if latest.payee_age_bucket == "new" and len(outbound) == 0 else 0.0

    complete = 0
    expired = 0
    for e in touching:
        if e.institution_id and e.rail and e.amount_bucket and e.payee_age_bucket:
            complete += 1
        if (as_of - e.occurred_at).total_seconds() > evidence_ttl_s:
            expired += 1
    feats["evidence_coverage"] = round(complete / len(touching), 4)
    insts = {e.institution_id for e in touching}
    feats["participation_ratio"] = round(len(insts) / max(1, expected_institutions), 4)
    feats["freshness_seconds"] = max(0.0, (as_of - latest.occurred_at).total_seconds())
    feats["expired_fraction"] = round(expired / len(touching), 4)
    return feats


def motif_vector(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in MOTIF_FEATURE_NAMES]
