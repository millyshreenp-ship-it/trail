"""Research-only B0, B1, and HGB wrappers.

These wrappers call the canonical v2 vector builders and are never imported by
API startup.  They accept events and server-owned contexts only; planted truth
is an evaluator concern and is not an input to feature construction.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from app.detection.features_contract import (
    B0_CONTRACT,
    MOTIF_CONTRACT,
    MOTIF_FEATURE_HASH,
    b0_risk_index,
    b0_vector_for_event,
    b1_risk_index,
    feature_vector_for_event,
)


def _scoreable(context: Any) -> bool:
    failure = getattr(getattr(context, "failure_code", None), "value", getattr(context, "failure_code", None))
    return failure in (None, "NONE") and bool(getattr(context, "local_sufficient", True))


@dataclass(frozen=True)
class BaselineMetadata:
    candidate: str
    engine_version: str
    contract: str
    hyperparameters: dict[str, Any]
    seed: int
    unknown_policy: str = "UNKNOWN rows are abstentions and are never ranked or backfilled"


class B0Baseline:
    metadata = BaselineMetadata(
        candidate="b0-v2",
        engine_version="earlytrace-b0b1-heuristic-v2",
        contract=B0_CONTRACT,
        hyperparameters={
            "weights": [0.32, 0.18, 0.12, 0.15, 0.10, 0.13],
            "normalizers": "locked b0.v2 contract",
        },
        seed=0,
    )

    @staticmethod
    def score(event: Any, context: Any) -> float | None:
        if not _scoreable(context):
            return None
        return b0_risk_index(b0_vector_for_event(event, context, event.occurred_at))

    def predict(self, events: Sequence[Any], contexts: Sequence[Any]) -> list[float | None]:
        if len(events) != len(contexts):
            raise ValueError("events and contexts must have equal length")
        return [self.score(event, context) for event, context in zip(events, contexts)]


class B1Baseline:
    metadata = BaselineMetadata(
        candidate="b1-v2",
        engine_version="earlytrace-b0b1-heuristic-v2",
        contract=MOTIF_CONTRACT,
        hyperparameters={
            "weights": [0.34, 0.16, 0.14, 0.10, 0.06, 0.06, 0.06, 0.04, 0.04],
            "policy": "locked motif.v2 feature-linked policy",
        },
        seed=0,
    )

    @staticmethod
    def score(event: Any, context: Any) -> float | None:
        if not _scoreable(context):
            return None
        return b1_risk_index(feature_vector_for_event(event, context, event.occurred_at))

    def predict(self, events: Sequence[Any], contexts: Sequence[Any]) -> list[float | None]:
        if len(events) != len(contexts):
            raise ValueError("events and contexts must have equal length")
        return [self.score(event, context) for event, context in zip(events, contexts)]


@dataclass
class HGBBaseline:
    """Optional offline HGB candidate on the canonical motif.v2 vector."""

    seed: int = 0
    max_depth: int = 3
    max_iter: int = 40
    learning_rate: float = 0.1
    model: Any = None
    available: bool = False
    reason: str | None = None
    threshold: float | None = None

    @property
    def metadata(self) -> BaselineMetadata:
        return BaselineMetadata(
            candidate="hgb-motif-v2",
            engine_version="earlytrace-b0b1-heuristic-v2",
            contract=MOTIF_CONTRACT,
            hyperparameters={
                "max_depth": self.max_depth,
                "max_iter": self.max_iter,
                "learning_rate": self.learning_rate,
                "random_state": self.seed,
            },
            seed=self.seed,
        )

    @staticmethod
    def _vectors(events: Sequence[Any], contexts: Sequence[Any]) -> list[list[float]]:
        if len(events) != len(contexts):
            raise ValueError("events and contexts must have equal length")
        return [list(feature_vector_for_event(event, context, event.occurred_at).values) for event, context in zip(events, contexts)]

    def fit(self, events: Sequence[Any], contexts: Sequence[Any], labels: Sequence[int], *, expected_feature_hash: str = MOTIF_FEATURE_HASH) -> "HGBBaseline":
        self.model = None
        self.available = False
        self.threshold = None
        if expected_feature_hash != MOTIF_FEATURE_HASH:
            self.reason = "feature_contract_mismatch"
            return self
        if len(events) != len(contexts) or len(events) != len(labels):
            raise ValueError("events, contexts, and labels must have equal length")
        eligible = [
            index for index, context in enumerate(contexts)
            if _scoreable(context)
        ]
        fit_events = [events[index] for index in eligible]
        fit_labels = [labels[index] for index in eligible]
        if len(set(fit_labels)) < 2 or len(fit_labels) < 10:
            self.reason = "training split does not contain two classes and ten scoreable rows"
            return self
        try:
            from sklearn.ensemble import HistGradientBoostingClassifier
        except ImportError:
            self.reason = "scikit-learn is not installed"
            return self
        self.model = HistGradientBoostingClassifier(
            max_depth=self.max_depth,
            max_iter=self.max_iter,
            learning_rate=self.learning_rate,
            random_state=self.seed,
        )
        self.model.fit(self._vectors(fit_events, [contexts[index] for index in eligible]), fit_labels)
        self.available = True
        self.reason = None
        return self

    def predict(self, events: Sequence[Any], contexts: Sequence[Any]) -> list[float | None]:
        if len(events) != len(contexts):
            raise ValueError("events and contexts must have equal length")
        if not self.available or self.model is None:
            return [None] * len(events)
        eligible = [index for index, context in enumerate(contexts) if _scoreable(context)]
        output: list[float | None] = [None] * len(events)
        if not eligible:
            return output
        raw = self.model.predict_proba(
            self._vectors([events[index] for index in eligible], [contexts[index] for index in eligible])
        )[:, 1]
        for index, score in zip(eligible, raw):
            output[index] = round(float(score), 4)
        return output

    def select_threshold(self, calibration_scores: Sequence[float | None], calibration_labels: Sequence[int], *, alerts_per_thousand: float = 20.0) -> float | None:
        """Select an alert threshold from calibration data only."""
        if len(calibration_scores) != len(calibration_labels):
            raise ValueError("calibration scores and labels must have equal length")
        pairs = sorted(
            [(float(score), int(label)) for score, label in zip(calibration_scores, calibration_labels) if score is not None],
            reverse=True,
        )
        slots = int(len(calibration_labels) * alerts_per_thousand / 1000.0)
        if not pairs or slots <= 0:
            self.threshold = None
        else:
            self.threshold = pairs[min(slots, len(pairs)) - 1][0]
        return self.threshold


def vector_rows(events: Sequence[Any], contexts: Sequence[Any], *, contract: str = MOTIF_CONTRACT) -> list[list[float]]:
    if contract == MOTIF_CONTRACT:
        return [list(feature_vector_for_event(event, context, event.occurred_at).values) for event, context in zip(events, contexts)]
    if contract == B0_CONTRACT:
        return [list(b0_vector_for_event(event, context, event.occurred_at).values) for event, context in zip(events, contexts)]
    raise ValueError("unknown feature contract")


__all__ = ["B0Baseline", "B1Baseline", "BaselineMetadata", "HGBBaseline", "vector_rows"]
