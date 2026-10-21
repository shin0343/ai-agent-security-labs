"""Transparent binary metrics with explicit unknown, abstention and missing buckets."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class BinaryMetrics:
    TP: int = 0
    FP: int = 0
    TN: int = 0
    FN: int = 0
    abstained: int = 0
    missing: int = 0
    errored: int = 0
    unlabeled: int = 0

    @property
    def known_total(self) -> int:
        return self.TP + self.FP + self.TN + self.FN + self.abstained + self.missing + self.errored

    @property
    def emitted(self) -> int:
        return self.TP + self.FP + self.TN + self.FN

    @property
    def coverage(self) -> float | None:
        return round(self.emitted / self.known_total, 4) if self.known_total else None

    @property
    def precision(self) -> float | None:
        denominator = self.TP + self.FP
        return round(self.TP / denominator, 4) if denominator else None

    @property
    def recall(self) -> float | None:
        denominator = self.TP + self.FN
        return round(self.TP / denominator, 4) if denominator else None

    @property
    def f1(self) -> float | None:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None:
            return None
        if precision + recall == 0:
            return 0.0
        return round(2 * precision * recall / (precision + recall), 4)

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.update(
            {
                "known_total": self.known_total,
                "emitted": self.emitted,
                "coverage": self.coverage,
                "precision": self.precision,
                "recall": self.recall,
                "f1": self.f1,
                "metric_note": (
                    "Precision/recall are conditional on emitted binary decisions and exclude unlabeled, "
                    "abstained, missing and errored cases. Tiny synthetic fixtures are functional checks, "
                    "not estimated intrusion-detection accuracy."
                ),
            }
        )
        return data


def score_predictions(
    records: list[dict[str, Any]],
) -> BinaryMetrics:
    """records: {gold: bool|null, prediction: REVIEW|LOW|UNKNOWN|MISSING|ERROR}."""
    metrics = BinaryMetrics()
    for record in records:
        gold = record.get("gold")
        prediction = str(record.get("prediction", "MISSING"))
        if gold is None:
            metrics.unlabeled += 1
            continue
        if prediction == "ERROR":
            metrics.errored += 1
            continue
        if prediction == "MISSING":
            metrics.missing += 1
            continue
        if prediction == "UNKNOWN":
            metrics.abstained += 1
            continue
        predicted_positive = prediction == "REVIEW"
        if gold and predicted_positive:
            metrics.TP += 1
        elif gold and not predicted_positive:
            metrics.FN += 1
        elif not gold and predicted_positive:
            metrics.FP += 1
        else:
            metrics.TN += 1
    return metrics


def threshold_comparison(
    records: list[dict[str, Any]], thresholds: tuple[int, ...] = (0, 20, 40, 60, 80, 90)
) -> list[dict[str, Any]]:
    """Diagnostic table on the same fixture; never evidence of generalization."""
    table = []
    for threshold in thresholds:
        metrics = BinaryMetrics()
        for record in records:
            gold = record.get("gold")
            if gold is None or record.get("disposition") == "UNKNOWN" or record.get("score") is None:
                continue
            predicted_positive = int(record["score"]) >= threshold
            if gold and predicted_positive:
                metrics.TP += 1
            elif gold and not predicted_positive:
                metrics.FN += 1
            elif not gold and predicted_positive:
                metrics.FP += 1
            else:
                metrics.TN += 1
        table.append(
            {
                "threshold": threshold,
                **metrics.as_dict(),
                "caveat": "Same four-agent fixture; threshold comparison is diagnostic, not tuning evidence.",
            }
        )
    return table
