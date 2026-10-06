"""Frozen compatibility adapter for the audited EarlyTrace v1 evaluator.

The adapter is deliberately small: it keeps the old scorer and event-time
semantics available to the exact ``--days`` regression command without making
v1 a public v2 scoring contract.
"""
from app.detection.preauth import (  # noqa: F401
    ENGINE_VERSION,
    FEATURE_CONTRACT,
    PreAuthContext,
    _b0_score,
    events_to_transactions,
    score_pre_auth,
)

V1_ENGINE_VERSION = "earlytrace-b0b1-heuristic-v1"
V1_FEATURE_CONTRACT = "motif.v1"
V1_COMPATIBILITY = True
