"""Synthetic data simulator (Khanak).

Re-exports the public generator API so callers can:
    from app.simulator import generate_dataset, generate_scam_chain, ...
"""
from app.simulator.generator import (
    generate_cross_bank_hop,
    generate_dataset,
    generate_legitimate_transactions,
    generate_preauth_corpus,
    generate_preauth_corpus_v2,
    generate_scam_chain,
    generate_scam_fanin,
    generate_scam_fanout,
    generate_sim2_corpus,
    generate_story_corpus,
    CorpusConfig,
    scenario_mixed_patterns,
    scenario_north_star,
    scenario_preauth_mule_network,
    transactions_to_dicts,
    write_manifest,
    write_synthetic_jsonl,
)

__all__ = [
    "generate_dataset",
    "generate_legitimate_transactions",
    "generate_scam_chain",
    "generate_scam_fanout",
    "generate_scam_fanin",
    "generate_cross_bank_hop",
    "scenario_north_star",
    "scenario_mixed_patterns",
    "scenario_preauth_mule_network",
    "generate_preauth_corpus",
    "generate_preauth_corpus_v2",
    "generate_sim2_corpus",
    "generate_story_corpus",
    "CorpusConfig",
    "write_manifest",
    "transactions_to_dicts",
    "write_synthetic_jsonl",
]
