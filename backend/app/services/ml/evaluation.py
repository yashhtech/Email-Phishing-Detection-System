"""Evaluation metrics module for ML classifiers.

Calculates:
- Precision, Recall, F1 score (binary and macro-averaged multiclass)
- Accuracy, Specificity (True Negative Rate)
- ROC-AUC (Area Under Receiver Operating Characteristic Curve) using trapezoidal integration
- Confusion Matrix (TP, FP, TN, FN)
- Calibration metrics (Brier Score)
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class BinaryConfusionMatrix:
    """Standard 2x2 confusion matrix for binary classification (phishing vs clean)."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def total(self) -> int:
        return (
            self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        )


@dataclass(frozen=True)
class ClassificationMetrics:
    """Comprehensive performance metrics report."""

    accuracy: float
    precision: float
    recall: float
    f1_score: float
    specificity: float
    roc_auc: float | None
    brier_score: float
    confusion_matrix: BinaryConfusionMatrix


class ModelEvaluator:
    """Evaluates classifier outputs against ground truth labels."""

    @staticmethod
    def evaluate(
        y_true: Sequence[int],
        y_pred: Sequence[int],
        y_prob: Sequence[float] | None = None,
    ) -> ClassificationMetrics:
        """Calculate comprehensive classification metrics.

        Args:
            y_true: Ground truth binary labels (1 = positive/phishing, 0 = negative/clean).
            y_pred: Predicted binary labels (1 = positive/phishing, 0 = negative/clean).
            y_prob: Optional predicted probabilities for positive class (used for ROC-AUC and Brier).

        Returns:
            ClassificationMetrics instance.
        """
        if len(y_true) != len(y_pred):
            raise ValueError(
                f"Length mismatch: len(y_true)={len(y_true)} vs len(y_pred)={len(y_pred)}"
            )
        if len(y_true) == 0:
            raise ValueError("Cannot evaluate empty predictions list.")

        tp = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if yt == 1 and yp == 1)
        fp = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if yt == 0 and yp == 1)
        tn = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if yt == 0 and yp == 0)
        fn = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if yt == 1 and yp == 0)

        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        if (precision + recall) > 0:
            f1 = 2.0 * (precision * recall) / (precision + recall)
        else:
            f1 = 0.0

        # Brier score: mean squared error between probability and ground truth
        brier = 0.0
        if y_prob is not None and len(y_prob) == len(y_true):
            brier = sum((prob - yt) ** 2 for prob, yt in zip(y_prob, y_true, strict=True)) / total

        # ROC-AUC calculation via trapezoidal rule
        roc_auc = None
        if y_prob is not None and len(y_prob) == len(y_true):
            roc_auc = ModelEvaluator._compute_roc_auc(y_true, y_prob)

        return ClassificationMetrics(
            accuracy=round(accuracy, 4),
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            specificity=round(specificity, 4),
            roc_auc=round(roc_auc, 4) if roc_auc is not None else None,
            brier_score=round(brier, 4),
            confusion_matrix=BinaryConfusionMatrix(
                true_positives=tp,
                false_positives=fp,
                true_negatives=tn,
                false_negatives=fn,
            ),
        )

    @staticmethod
    def _compute_roc_auc(y_true: Sequence[int], y_prob: Sequence[float]) -> float:
        """Compute ROC-AUC non-parametrically using the Mann-Whitney U statistic."""
        positives = [p for p, yt in zip(y_prob, y_true, strict=True) if yt == 1]
        negatives = [p for p, yt in zip(y_prob, y_true, strict=True) if yt == 0]

        n_pos = len(positives)
        n_neg = len(negatives)

        if n_pos == 0 or n_neg == 0:
            return 0.5  # Undefined single-class edge case

        # Count pairs where positive score > negative score (ties count as 0.5)
        concordant = 0.0
        for p in positives:
            for neg in negatives:
                if p > neg:
                    concordant += 1.0
                elif p == neg:
                    concordant += 0.5

        return concordant / (n_pos * n_neg)
