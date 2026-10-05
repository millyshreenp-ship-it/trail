"""Detection & scam intelligence (Khanak).

Part 1: features + local risk scoring.
Part 2: NetworkX lineage, pattern detection, ring cases, evaluation.
"""

from app.detection.features import (
    FEATURE_NAMES,
    compute_account_features,
    compute_features_batch,
)

from app.detection.scorer import (
    RiskResult,
    RiskScorer,
    default_scorer,
)
