"""Fund lineage graphs with NetworkX (Khanak).

Two construction paths:
  1. From beacons (hub path — what try_detect / build_ring_record uses)
  2. From synthetic transactions (simulator / evaluation path)

Node attributes: institution, amount_bucket, edge_type, issued_at, ...
Edge attributes: edge_type, amount_bucket
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Iterable, Sequence

import networkx as nx

from app.models.beacon import BUCKET_BOUNDS, AMOUNT_BUCKETS, Beacon, EdgeType
from app.models.transaction import Transaction

# Mid / lo / hi helpers for bucketed amounts (synthetic INR)
_BUCKET_LO = {name: lo for name, (lo, _hi) in zip(AMOUNT_BUCKETS, BUCKET_BOUNDS)}
_BUCKET_HI = {
    name: (hi if hi is not None else lo * 2)
    for name, (lo, hi) in zip(AMOUNT_BUCKETS, BUCKET_BOUNDS)
}
_BUCKET_MID = {
    name: (lo + (hi if hi is not None else lo * 2)) / 2.0
    for name, (lo, hi) in zip(AMOUNT_BUCKETS, BUCKET_BOUNDS)
}


def bucket_lo(bucket: str | None) -> float:
    return float(_BUCKET_LO.get(bucket or "0_1k", 0.0))


def bucket_hi(bucket: str | None) -> float:
    return float(_BUCKET_HI.get(bucket or "0_1k", 1_000.0))


def bucket_mid(bucket: str | None) -> float:
    return float(_BUCKET_MID.get(bucket or "0_1k", 500.0))


def parallel_edge_data(G: nx.DiGraph, source: str, dest: str) -> list[dict]:
    """Every parallel transfer between two tokens. DiGraph callers still see one edge."""
    if not G.has_edge(source, dest):
        return []
    if G.is_multigraph():
        return [dict(data) for data in G[source][dest].values()]
    return [dict(G.edges[source, dest])]


def build_beacon_graph(beacons: Sequence[Beacon]) -> nx.MultiDiGraph:
    """Directed multigraph: parent_token → token. Parallel beacons stay distinct edges."""
    G = nx.MultiDiGraph()
    for b in beacons:
        attrs = {
            "institution": b.institution_id,
            "amount_bucket": b.amount_bucket,
            "edge_type": b.edge_type.value if isinstance(b.edge_type, EdgeType) else str(b.edge_type),
            "issued_at": b.issued_at,
            "rail": b.rail,
            "time_bucket": b.time_bucket,
            "taint_lo_bucket": b.taint_lo_bucket,
            "taint_hi_bucket": b.taint_hi_bucket,
        }
        if b.token not in G:
            G.add_node(b.token, **attrs)
        else:
            # Prefer richer attrs if node already exists (e.g. behavioural after derived)
            G.nodes[b.token].update({k: v for k, v in attrs.items() if v is not None})

        if b.parent_token:
            if b.parent_token not in G:
                G.add_node(b.parent_token, institution="UNKNOWN", amount_bucket=b.amount_bucket,
                           edge_type="inferred_parent", issued_at=b.issued_at, rail=b.rail)
            G.add_edge(
                b.parent_token,
                b.token,
                edge_type=attrs["edge_type"],
                amount_bucket=b.amount_bucket,
                institution=b.institution_id,
                issued_at=b.issued_at,
            )
    return G


def build_transaction_graph(transactions: Sequence[Transaction]) -> nx.MultiDiGraph:
    """Directed multigraph of account tokens. Repeated transfers are separate edges."""
    G = nx.MultiDiGraph()
    for t in transactions:
        for node, inst in ((t.source_token, t.source_institution),
                           (t.destination_token, t.destination_institution)):
            if node not in G:
                G.add_node(node, institution=inst, first_ts=t.timestamp, last_ts=t.timestamp)
            else:
                G.nodes[node]["last_ts"] = max(G.nodes[node].get("last_ts", t.timestamp), t.timestamp)
                G.nodes[node]["first_ts"] = min(G.nodes[node].get("first_ts", t.timestamp), t.timestamp)
        G.add_edge(
            t.source_token,
            t.destination_token,
            transaction_id=t.transaction_id,
            amount_bucket=t.amount_bucket,
            timestamp=t.timestamp,
            rail=t.rail,
            reference_token=t.reference_token,
            source_institution=t.source_institution,
            destination_institution=t.destination_institution,
        )
    return G


def subgraph_from_seed(G: nx.DiGraph, seed_token: str) -> nx.DiGraph:
    """All nodes reachable from seed (including seed). Preserves multi-edges."""
    if seed_token not in G:
        return nx.MultiDiGraph() if G.is_multigraph() else nx.DiGraph()
    reachable = nx.descendants(G, seed_token) | {seed_token}
    return G.subgraph(reachable).copy()


def longest_path_from(G: nx.DiGraph, seed: str) -> list[str]:
    """Longest simple path starting at seed (for chain / hop patterns)."""
    if seed not in G:
        return []
    best: list[str] = [seed]
    # DAG-friendly DP; beacon graphs are typically trees/DAGs
    if nx.is_directed_acyclic_graph(G):
        topo = list(nx.topological_sort(G))
        dist = {n: (0, [n]) for n in G.nodes}
        for n in topo:
            if n not in dist:
                continue
            d, path = dist[n]
            for succ in G.successors(n):
                nd = d + 1
                if nd > dist.get(succ, (-1, []))[0]:
                    dist[succ] = (nd, path + [succ])
        if seed in dist:
            # among nodes reachable from seed, pick max depth
            for n in nx.descendants(G, seed) | {seed}:
                if n in dist and dist[n][0] > len(best) - 1:
                    best = dist[n][1]
        return best
    # Fallback BFS layers for rare cycles
    from collections import deque
    q: deque[list[str]] = deque([[seed]])
    while q:
        path = q.popleft()
        if len(path) > len(best):
            best = path
        for succ in G.successors(path[-1]):
            if succ not in path:
                q.append(path + [succ])
    return best


def fanout_centers(G: nx.DiGraph, min_out: int = 3) -> list[str]:
    return [n for n in G.nodes if G.out_degree(n) >= min_out]


def fanin_centers(G: nx.DiGraph, min_in: int = 3) -> list[str]:
    return [n for n in G.nodes if G.in_degree(n) >= min_in]


def institutions_on_path(G: nx.DiGraph, path: Sequence[str]) -> list[str]:
    seen: list[str] = []
    for n in path:
        inst = G.nodes[n].get("institution") or "UNKNOWN"
        if not seen or seen[-1] != inst:
            seen.append(inst)
    return seen


def minutes_between(issued_a: int | None, issued_b: int | None) -> float:
    if issued_a is None or issued_b is None:
        return 0.0
    return max(0.0, (issued_b - issued_a) / 60.0)
