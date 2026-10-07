"""Exact, checksumable metadata for offline EarlyTrace candidates."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
from pathlib import Path
from typing import Any, Mapping

from app.detection.features_contract import (
    B0_CONTRACT,
    B0_FEATURE_HASH,
    B0_FEATURE_NAMES,
    MOTIF_CONTRACT,
    MOTIF_FEATURE_HASH,
    MOTIF_V2_FEATURE_NAMES,
)
from app.security.canonical_json import canonical_json_bytes


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def sha256_file(path: str | Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def dependency_lock_hash(path: str | Path | None = None) -> str | None:
    if path is None:
        return None
    candidate = Path(path)
    return sha256_file(candidate) if candidate.exists() else None


def resolved_library_versions(*, include_sklearn: bool = False) -> dict[str, str]:
    versions = {"python": platform.python_version()}
    if include_sklearn:
        try:
            versions["scikit-learn"] = importlib.metadata.version("scikit-learn")
        except importlib.metadata.PackageNotFoundError:
            versions["scikit-learn"] = "unavailable"
    return versions


def contract_metadata(contract: str) -> dict[str, Any]:
    if contract == B0_CONTRACT:
        names, digest = B0_FEATURE_NAMES, B0_FEATURE_HASH
    elif contract == MOTIF_CONTRACT:
        names, digest = MOTIF_V2_FEATURE_NAMES, MOTIF_FEATURE_HASH
    else:
        raise ValueError("unknown feature contract")
    return {
        "name": contract,
        "dimension": len(names),
        "ordered_names": list(names),
        "hash": digest,
        "value_type": "finite_float",
    }


def build_candidate_manifest(
    *,
    candidate: str,
    engine_version: str,
    contract: str,
    generator_version: str,
    event_checksum: str,
    label_checksum: str,
    vector_checksum: str,
    split_checksum: str,
    seed: int,
    unknown_policy: str,
    hyperparameters: Mapping[str, Any],
    class_weights: Mapping[str, float] | str | None = None,
    calibration_method: str = "none",
    calibration_owner: str = "not_calibrated",
    threshold_rule: str = "policy_action_or_floor_budget_on_calibration_only",
    threshold: float | None = None,
    artifact_checksum: str | None = None,
    lock_path: str | Path | None = None,
    library_versions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build one candidate manifest with no implicit defaults hidden from review."""
    manifest = {
        "manifest_version": "earlytrace-research-manifest-v2",
        "candidate": candidate,
        "research_only": True,
        "engine_version": engine_version,
        "feature_contract": contract_metadata(contract),
        "generator_version": generator_version,
        "event_checksum": event_checksum,
        "label_checksum": label_checksum,
        "vector_checksum": vector_checksum,
        "split_checksum": split_checksum,
        "unknown_policy": unknown_policy,
        "class_weights": class_weights,
        "hyperparameters": dict(hyperparameters),
        "seed": seed,
        "calibration": {
            "method": calibration_method,
            "owner": calibration_owner,
            "status": "not_fitted" if calibration_method == "none" else "research_artifact_only",
        },
        "threshold_rule": threshold_rule,
        "threshold": threshold,
        "artifact_checksum": artifact_checksum,
        "dependency_lock_hash": dependency_lock_hash(lock_path),
        "dependency_lock_status": "verified" if dependency_lock_hash(lock_path) else "not_present",
        "library_versions": dict(library_versions or resolved_library_versions()),
        "score_semantics": "risk_index; not a probability unless a matching calibration artifact is verified",
        "rmse_policy": "not_optimized; if emitted, lower is better and it is secondary",
    }
    manifest["manifest_checksum"] = sha256_json(manifest)
    return manifest


def write_candidate_manifest(path: str | Path, manifest: Mapping[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(dict(manifest), indent=2, sort_keys=True), encoding="utf-8")


__all__ = [
    "build_candidate_manifest",
    "contract_metadata",
    "dependency_lock_hash",
    "resolved_library_versions",
    "sha256_bytes",
    "sha256_file",
    "sha256_json",
    "write_candidate_manifest",
]
