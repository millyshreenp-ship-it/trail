"""Frozen v1 motif boundary used only by the legacy evaluator.

This module intentionally re-exports the audited v1 implementation.  New
runtime contracts must not import it.
"""
from app.detection.motifs import (  # noqa: F401
    EventIndex,
    MOTIF_FEATURE_NAMES,
    MotifEvent,
    build_event_index,
    extract_motif_features,
    motif_vector,
)

V1_FEATURE_CONTRACT = "motif.v1"
