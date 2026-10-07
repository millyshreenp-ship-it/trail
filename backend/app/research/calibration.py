"""Fail-closed calibration artifacts for offline EarlyTrace research."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.research.manifests import resolved_library_versions, sha256_json


class CalibrationMismatch(ValueError):
    """The artifact cannot be used with the requested run."""


@dataclass(frozen=True)
class CalibrationArtifact:
    candidate: str
    engine_version: str
    feature_contract: str
    feature_hash: str
    feature_dimension: int
    feature_names: tuple[str, ...]
    generator_version: str
    event_checksum: str
    label_checksum: str
    vector_checksum: str
    split_checksum: str
    fit_boundary: str
    calibration_boundary: str
    seed: int
    method: str = "platt_logistic"
    library_versions: Mapping[str, str] = field(default_factory=resolved_library_versions)
    threshold_rule: str = "calibration_only_floor_budget"
    threshold: float | None = None
    parameters: Mapping[str, float] = field(default_factory=dict)
    dependency_lock_hash: str | None = None
    created_at: str = ""
    expires_at: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": "earlytrace-calibration-v2",
            "candidate": self.candidate,
            "engine_version": self.engine_version,
            "feature_contract": self.feature_contract,
            "feature_hash": self.feature_hash,
            "feature_dimension": self.feature_dimension,
            "feature_names": list(self.feature_names),
            "generator_version": self.generator_version,
            "event_checksum": self.event_checksum,
            "label_checksum": self.label_checksum,
            "vector_checksum": self.vector_checksum,
            "split_checksum": self.split_checksum,
            "fit_boundary": self.fit_boundary,
            "calibration_boundary": self.calibration_boundary,
            "seed": self.seed,
            "method": self.method,
            "library_versions": dict(self.library_versions),
            "threshold_rule": self.threshold_rule,
            "threshold": self.threshold,
            "parameters": dict(self.parameters),
            "dependency_lock_hash": self.dependency_lock_hash,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    @property
    def artifact_checksum(self) -> str:
        return sha256_json(self.payload())

    def as_dict(self) -> dict[str, Any]:
        payload = self.payload()
        payload["artifact_checksum"] = self.artifact_checksum
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CalibrationArtifact":
        raw = dict(payload)
        checksum = raw.pop("artifact_checksum", None)
        raw.pop("schema_version", None)
        artifact = cls(
            candidate=str(raw["candidate"]),
            engine_version=str(raw["engine_version"]),
            feature_contract=str(raw["feature_contract"]),
            feature_hash=str(raw["feature_hash"]),
            feature_dimension=int(raw["feature_dimension"]),
            feature_names=tuple(raw["feature_names"]),
            generator_version=str(raw["generator_version"]),
            event_checksum=str(raw["event_checksum"]),
            label_checksum=str(raw["label_checksum"]),
            vector_checksum=str(raw["vector_checksum"]),
            split_checksum=str(raw["split_checksum"]),
            fit_boundary=str(raw["fit_boundary"]),
            calibration_boundary=str(raw["calibration_boundary"]),
            seed=int(raw["seed"]),
            method=str(raw.get("method", "platt_logistic")),
            library_versions=dict(raw.get("library_versions", {})),
            threshold_rule=str(raw.get("threshold_rule", "calibration_only_floor_budget")),
            threshold=raw.get("threshold"),
            parameters=dict(raw.get("parameters", {})),
            dependency_lock_hash=raw.get("dependency_lock_hash"),
            created_at=str(raw.get("created_at", "")),
            expires_at=raw.get("expires_at"),
        )
        if checksum != artifact.artifact_checksum:
            raise CalibrationMismatch("calibration artifact checksum mismatch")
        return artifact


def _now() -> datetime:
    return datetime.now(timezone.utc)


def validate_calibration_artifact(
    artifact: CalibrationArtifact,
    expected: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> None:
    """Validate every identity field before a calibrated score is exposed."""
    if artifact.artifact_checksum != sha256_json(artifact.payload()):
        raise CalibrationMismatch("calibration artifact checksum mismatch")
    for key in (
        "candidate", "engine_version", "feature_contract", "feature_hash",
        "feature_dimension", "generator_version", "event_checksum",
        "label_checksum", "vector_checksum", "split_checksum", "seed",
    ):
        if key in expected and getattr(artifact, key) != expected[key]:
            raise CalibrationMismatch(f"calibration metadata mismatch: {key}")
    if "feature_names" in expected and tuple(expected["feature_names"]) != artifact.feature_names:
        raise CalibrationMismatch("calibration feature order mismatch")
    if artifact.method != "platt_logistic":
        raise CalibrationMismatch("unsupported calibration method")
    if artifact.expires_at:
        current = (now or _now()).astimezone(timezone.utc)
        expiry = datetime.fromisoformat(artifact.expires_at)
        if expiry.tzinfo is None or current >= expiry.astimezone(timezone.utc):
            raise CalibrationMismatch("calibration artifact is stale")


def fit_platt_artifact(
    raw_scores: Sequence[float],
    labels: Sequence[int],
    *,
    metadata: Mapping[str, Any],
    seed: int = 0,
    threshold: float | None = None,
    expires_at: datetime | None = None,
) -> CalibrationArtifact:
    """Fit Platt only on a declared calibration window."""
    if len(raw_scores) != len(labels) or len(raw_scores) < 8 or len(set(labels)) < 2:
        raise CalibrationMismatch("calibration window lacks two-class support")
    try:
        from sklearn.linear_model import LogisticRegression
        library = resolved_library_versions(include_sklearn=True)
    except ImportError as exc:
        raise CalibrationMismatch("scikit-learn is unavailable") from exc
    model = LogisticRegression(random_state=seed)
    model.fit([[float(score)] for score in raw_scores], list(labels))
    created = _now().isoformat()
    return CalibrationArtifact(
        candidate=str(metadata["candidate"]),
        engine_version=str(metadata["engine_version"]),
        feature_contract=str(metadata["feature_contract"]),
        feature_hash=str(metadata["feature_hash"]),
        feature_dimension=int(metadata["feature_dimension"]),
        feature_names=tuple(metadata["feature_names"]),
        generator_version=str(metadata["generator_version"]),
        event_checksum=str(metadata["event_checksum"]),
        label_checksum=str(metadata["label_checksum"]),
        vector_checksum=str(metadata["vector_checksum"]),
        split_checksum=str(metadata["split_checksum"]),
        fit_boundary=str(metadata["fit_boundary"]),
        calibration_boundary=str(metadata["calibration_boundary"]),
        seed=seed,
        method="platt_logistic",
        library_versions=library,
        threshold_rule="calibration_only_floor_budget",
        threshold=threshold,
        parameters={"coef": float(model.coef_[0][0]), "intercept": float(model.intercept_[0])},
        dependency_lock_hash=metadata.get("dependency_lock_hash"),
        created_at=created,
        expires_at=expires_at.isoformat() if expires_at else None,
    )


def calibrated_scores(artifact: CalibrationArtifact, raw_scores: Sequence[float], *, expected: Mapping[str, Any]) -> list[float]:
    validate_calibration_artifact(artifact, expected)
    coefficient = float(artifact.parameters["coef"])
    intercept = float(artifact.parameters["intercept"])
    import math
    return [round(1.0 / (1.0 + math.exp(-(coefficient * float(score) + intercept))), 4) for score in raw_scores]


def write_calibration(path: str | Path, artifact: CalibrationArtifact) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(artifact.as_dict(), indent=2, sort_keys=True), encoding="utf-8")


def load_calibration(path: str | Path, expected: Mapping[str, Any], *, now: datetime | None = None) -> CalibrationArtifact:
    artifact = CalibrationArtifact.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
    validate_calibration_artifact(artifact, expected, now=now)
    return artifact


__all__ = [
    "CalibrationArtifact",
    "CalibrationMismatch",
    "calibrated_scores",
    "fit_platt_artifact",
    "load_calibration",
    "validate_calibration_artifact",
    "write_calibration",
]
