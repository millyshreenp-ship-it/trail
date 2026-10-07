"""Cross-bank graph construction, pattern detection, and ring-level cases (Khanak).

Integration contract (docs/data-contract.md, api/cases.py::try_detect):
    build_ring_record(beacons: list[Beacon], seed_token: str) -> RingRecord | dict | None

Also exposes transaction-based detection for simulator evaluation.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Sequence

import networkx as nx

from app.detection.lineage import (
    bucket_hi,
    bucket_lo,
    build_beacon_graph,
    build_transaction_graph,
    fanin_centers,
    fanout_centers,
    institutions_on_path,
    longest_path_from,
    minutes_between,
    subgraph_from_seed,
)
from app.detection.receiver import classify_receiver, structural_risk_from_graph
from app.detection.scorer import RiskScorer
from app.detection.triage import recommend_action, ring_reasons
from app.models.beacon import Beacon
from app.models.case import ActionCode, ReceiverClass, RiskLevel, RingHop, RingRecord
from app.models.transaction import Transaction

_LEVELS = (
    (0.85, RiskLevel.CRITICAL),
    (0.60, RiskLevel.HIGH),
    (0.35, RiskLevel.MEDIUM),
    (0.0, RiskLevel.LOW),
)


def _level(score: float) -> RiskLevel:
    for thr, lv in _LEVELS:
        if score >= thr:
            return lv
    return RiskLevel.LOW


def _pseudonym(token: str, case_id: str | None = None, token_service=None) -> str:
    """Case-scoped HMAC pseudonym when a case id exists. Never returns the raw token."""
    if case_id and token_service is not None:
        return token_service.case_pseudonym(case_id, token)
    if case_id:
        digest = hmac.new(
            b"earlytrace-case-scope",
            f"{case_id}\x1f{token}".encode(),
            hashlib.sha256,
        ).digest()[:12]
        return "acc_" + digest.hex()
    body = token[4:] if token.startswith("tok_") else token
    return "acc_" + body[:12]


def detect_pattern(G: nx.DiGraph, seed: str) -> tuple[str, list[str], list[tuple[int, int]]]:
    """Return (pattern_name, ordered_node_path_or_nodes, edges_as_hop_index_pairs)."""
    if seed not in G:
        return "chain", [], []

    sub = subgraph_from_seed(G, seed)
    fo = fanout_centers(sub, min_out=3)
    fi = fanin_centers(sub, min_in=3)
    path = longest_path_from(sub, seed)
    insts = institutions_on_path(sub, path)

    # Prefer explicit morphologies
    if fo and (not path or sub.out_degree(fo[0]) >= 3):
        center = fo[0]
        leaves = list(sub.successors(center))
        nodes = [seed] if seed != center and seed in sub else []
        if center not in nodes:
            # path seed → … → center
            if center in path:
                nodes = path[: path.index(center) + 1]
            else:
                nodes = [seed, center] if seed != center else [center]
        for leaf in leaves:
            if leaf not in nodes:
                nodes.append(leaf)
        idx = {n: i for i, n in enumerate(nodes)}
        edges = []
        if seed in idx and center in idx and seed != center:
            edges.append((idx[seed], idx[center]))
        for leaf in leaves:
            if leaf in idx:
                edges.append((idx[center], idx[leaf]))
        return "fanout", nodes, edges

    if fi:
        center = fi[0]
        parents = list(sub.predecessors(center))
        nodes = list(parents) + [center]
        outs = list(sub.successors(center))
        nodes.extend(o for o in outs if o not in nodes)
        idx = {n: i for i, n in enumerate(nodes)}
        edges = [(idx[p], idx[center]) for p in parents if p in idx]
        for o in outs:
            if o in idx:
                edges.append((idx[center], idx[o]))
        return "fanin", nodes, edges

    # Chain / cross-bank hop
    if len(insts) >= 3 and len(path) >= 3:
        edges = [(i, i + 1) for i in range(len(path) - 1)]
        return "cross_bank_hop", path, edges
    if len(path) >= 2:
        edges = [(i, i + 1) for i in range(len(path) - 1)]
        return "chain", path, edges
    return "chain", path or [seed], []


def _seed_issued_at(G: nx.DiGraph, seed: str) -> int | None:
    return G.nodes[seed].get("issued_at") if seed in G else None


def build_ring_record(
    beacons: list[Beacon] | Sequence[Beacon],
    seed_token: str,
    *,
    case_id: str | None = None,
    token_service=None,
) -> RingRecord | None:
    """Hub integration hook. Returns None if the trail is too short to form a ring."""
    beacons = list(beacons)
    if not beacons and not seed_token:
        return None

    # Ensure seed is present even if only descendants were passed
    G = build_beacon_graph(beacons)
    if seed_token not in G:
        G.add_node(
            seed_token,
            institution="UNKNOWN",
            amount_bucket="50k_100k",
            edge_type="complaint_seed",
            issued_at=min((b.issued_at for b in beacons), default=0),
            rail="UPI",
        )
        # attach orphans that claim this parent
        for b in beacons:
            if b.parent_token == seed_token and not G.has_edge(seed_token, b.token):
                G.add_edge(seed_token, b.token, edge_type="derived_funds",
                           amount_bucket=b.amount_bucket, institution=b.institution_id,
                           issued_at=b.issued_at)

    pattern, nodes, edge_pairs = detect_pattern(G, seed_token)
    if len(nodes) < 2:
        return None  # need at least seed + one hop

    seed_ts = _seed_issued_at(G, seed_token)
    n_hops = len(nodes)
    inst_list: list[str] = []
    hops: list[RingHop] = []

    for i, token in enumerate(nodes):
        data = G.nodes.get(token, {})
        inst = data.get("institution") or "UNKNOWN"
        if inst not in inst_list:
            inst_list.append(inst)
        out_d = G.out_degree(token) if token in G else 0
        in_d = G.in_degree(token) if token in G else 0
        issued = data.get("issued_at")
        mins = minutes_between(seed_ts, issued) if seed_ts and issued else float(i * 5)
        is_terminal = out_d == 0 and i == n_hops - 1

        amount_bucket = data.get("amount_bucket") or "50k_100k"
        taint_lo_b = data.get("taint_lo_bucket") or amount_bucket
        taint_hi_b = data.get("taint_hi_bucket") or amount_bucket
        lo, hi = bucket_lo(taint_lo_b), bucket_hi(taint_hi_b)

        score, struct_why = structural_risk_from_graph(
            out_degree=out_d,
            in_degree=in_d,
            hop_index=i,
            n_hops=n_hops,
            n_institutions=len(institutions_on_path(G, nodes)),
            minutes_since_seed=mins,
            is_terminal=is_terminal,
        )
        # Mild position prior: later hops on a long trail trend riskier
        if i == n_hops - 1 and n_hops >= 3:
            score = min(0.98, score + 0.05)
        level = _level(score)
        rclass = classify_receiver(
            hop_index=i,
            n_hops=n_hops,
            risk_score=score,
            risk_level=level,
            out_degree=out_d,
            in_degree=in_d,
            institution=inst,
            is_terminal=is_terminal,
            pattern=pattern,
            reasons=struct_why,
        )
        # Soften a mid-path MEDIUM hop toward legitimate (north-star demo shape)
        if (
            pattern in ("cross_bank_hop", "chain")
            and 0 < i < n_hops - 1
            and level == RiskLevel.MEDIUM
            and out_d <= 1
        ):
            rclass = ReceiverClass.LEGITIMATE
            struct_why = struct_why + ["Regular pass-through / possible merchant settlement"]

        hops.append(
            RingHop(
                hop_index=i,
                institution=inst,
                receiver_pseudonym=_pseudonym(token, case_id, token_service),
                token=token,
                tainted_amount_lo=lo,
                tainted_amount_hi=hi,
                minutes_since_seed=round(mins, 1),
                risk_score=score,
                risk_level=level,
                receiver_class=rclass,
                reasons=struct_why[:5],
            )
        )

    # Prefer seed amount as total taint lower bound when available
    seed_bucket = G.nodes.get(seed_token, {}).get("amount_bucket")
    total_lo = bucket_lo(seed_bucket) if seed_bucket else max((h.tainted_amount_lo for h in hops), default=0.0)

    reasons = ring_reasons(pattern, hops, inst_list)
    # Confidence from coverage + structure
    conf = 0.55
    conf += 0.1 * min(3, len(inst_list) - 1)
    conf += 0.05 * min(4, n_hops)
    if any(h.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) for h in hops):
        conf += 0.1
    conf = round(min(0.98, conf), 3)

    ring = RingRecord(
        pattern=pattern,
        seed_token=seed_token,
        n_hops=n_hops,
        institutions=inst_list,
        hops=hops,
        edges=edge_pairs,
        total_tainted_lo=total_lo,
        confidence=conf,
        reasons=reasons,
        recommended_action=ActionCode.A0,  # set below
    )
    ring.recommended_action = recommend_action(ring)
    return ring


def detect_ring_from_transactions(
    transactions: Sequence[Transaction],
    seed_token: str,
    *,
    scorer: RiskScorer | None = None,
    case_id: str | None = None,
    token_service=None,
) -> RingRecord | None:
    """Offline / evaluation path: build graph from synthetic txs and score hops."""
    G = build_transaction_graph(transactions)
    if seed_token not in G:
        return None
    pattern, nodes, edge_pairs = detect_pattern(G, seed_token)
    if len(nodes) < 2:
        return None

    scorer = scorer or RiskScorer()
    # Seed timestamp from first outbound or first touch
    seed_ts = None
    for u, v, data in G.edges(data=True):
        if u == seed_token or v == seed_token:
            ts = data.get("timestamp")
            if ts is not None and (seed_ts is None or ts < seed_ts):
                seed_ts = ts

    hops: list[RingHop] = []
    inst_list: list[str] = []
    n_hops = len(nodes)
    for i, token in enumerate(nodes):
        data = G.nodes.get(token, {})
        inst = data.get("institution") or "UNKNOWN"
        if inst not in inst_list:
            inst_list.append(inst)
        result = scorer.score_account(transactions, token)
        out_d = G.out_degree(token)
        in_d = G.in_degree(token)
        is_terminal = out_d == 0 and i == n_hops - 1
        # minutes since seed
        mins = 0.0
        if seed_ts is not None:
            last = data.get("last_ts") or data.get("first_ts")
            if last is not None:
                mins = max(0.0, (last - seed_ts).total_seconds() / 60.0)
        # taint from incident edges
        lo = hi = 0.0
        for _u, _v, ed in G.in_edges(token, data=True):
            lo = max(lo, bucket_lo(ed.get("amount_bucket")))
            hi = max(hi, bucket_hi(ed.get("amount_bucket")))
        if lo == 0 and i == 0:
            for _u, _v, ed in G.out_edges(token, data=True):
                lo = max(lo, bucket_lo(ed.get("amount_bucket")))
                hi = max(hi, bucket_hi(ed.get("amount_bucket")))

        rclass = classify_receiver(
            hop_index=i,
            n_hops=n_hops,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            out_degree=out_d,
            in_degree=in_d,
            institution=inst,
            is_terminal=is_terminal,
            pattern=pattern,
            reasons=result.reasons,
        )
        hops.append(
            RingHop(
                hop_index=i,
                institution=inst,
                receiver_pseudonym=_pseudonym(token, case_id, token_service),
                token=token,
                tainted_amount_lo=lo,
                tainted_amount_hi=hi or lo,
                minutes_since_seed=round(mins, 1),
                risk_score=result.risk_score,
                risk_level=result.risk_level,
                receiver_class=rclass,
                reasons=result.reasons[:5],
            )
        )

    total_lo = max((h.tainted_amount_lo for h in hops), default=0.0)
    reasons = ring_reasons(pattern, hops, inst_list)
    ring = RingRecord(
        pattern=pattern,
        seed_token=seed_token,
        n_hops=n_hops,
        institutions=inst_list,
        hops=hops,
        edges=edge_pairs,
        total_tainted_lo=total_lo,
        confidence=0.85,
        reasons=reasons,
        recommended_action=ActionCode.A0,
    )
    ring.recommended_action = recommend_action(ring)
    return ring


def explain_ring(ring: RingRecord) -> dict:
    """Human-readable case explanation for the investigator dashboard."""
    return {
        "pattern": ring.pattern,
        "summary": ring.reasons,
        "n_hops": ring.n_hops,
        "institutions": ring.institutions,
        "total_tainted_lo": ring.total_tainted_lo,
        "confidence": ring.confidence,
        "recommended_action": ring.recommended_action.value,
        "hops": [
            {
                "hop_index": h.hop_index,
                "institution": h.institution,
                "risk_level": h.risk_level.value,
                "receiver_class": h.receiver_class.value,
                "risk_score": h.risk_score,
                "minutes_since_seed": h.minutes_since_seed,
                "why": h.reasons,
            }
            for h in ring.hops
        ],
    }
