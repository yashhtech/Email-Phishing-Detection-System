"""Inference service for ML email classification.

Responsibilities:
- Coordinate FeatureExtractor and active model from ModelRegistry
- Measure inference latency precisely with monotonic clocks
- Return structured MLInferenceResult containing:
    classification
    probability
    confidence
    model_version
    features_used
    inference_latency_ms
- Catch and recover gracefully from any model failure using FallbackClassifier
- Never hardcode predictions; all scores derive from feature vectors and model weights
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import structlog

from app.domain.entities.email_analysis_input import EmailAnalysisInput
from app.services.ml.classifier import ClassifierOutput, FallbackClassifier
from app.services.ml.feature_extractor import FeatureExtractor
from app.services.ml.model_registry import ModelRegistry

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class MLInferenceResult:
    """Canonical output returned by ML inference engine."""

    classification: str  # "phishing", "spam", "clean"
    probability: float  # [0.0, 1.0] primary class probability
    phishing_probability: float  # [0.0, 1.0]
    spam_probability: float  # [0.0, 1.0]
    clean_probability: float  # [0.0, 1.0]
    confidence: float  # [0.0, 1.0]
    model_version: str  # Version tag of the model that produced this prediction
    features_used: dict[str, float]  # Names and values of extracted features
    feature_contributions: dict[str, float]  # Explainability weights / SHAP approximations
    inference_latency_ms: float  # Wall-clock inference time in milliseconds


class MLInferenceService:
    """Thread-safe inference coordinator for ML-based email threat detection."""

    def __init__(
        self,
        registry: ModelRegistry | None = None,
        feature_extractor: FeatureExtractor | None = None,
    ) -> None:
        self.registry = registry or ModelRegistry()
        self.feature_extractor = feature_extractor or FeatureExtractor()
        self._fallback_classifier = FallbackClassifier()

    def predict(
        self,
        email_input: EmailAnalysisInput,
        model_version: str | None = None,
    ) -> MLInferenceResult:
        """Run ML inference over an EmailAnalysisInput.

        Args:
            email_input: Canonical preprocessed email data.
            model_version: Optional version override. If None, default model is used.

        Returns:
            MLInferenceResult with probability, confidence, latency, and features.
        """
        start_time = time.perf_counter()

        # 1. Feature extraction
        feature_res = self.feature_extractor.extract(email_input)
        features = feature_res.features
        vector = feature_res.feature_vector

        # 2. Model selection and inference with error recovery
        model = self.registry.get_model(model_version)
        try:
            output: ClassifierOutput = model.predict(vector, features)
        except Exception as exc:
            logger.error(
                "model_inference_failed_falling_back",
                error=str(exc),
                model=model.model_name,
                version=model.model_version,
            )
            output = self._fallback_classifier.predict(vector, features)

        end_time = time.perf_counter()
        latency_ms = round((end_time - start_time) * 1000.0, 3)

        return MLInferenceResult(
            classification=output.label,
            probability=output.probability,
            phishing_probability=output.phishing_probability,
            spam_probability=output.spam_probability,
            clean_probability=output.clean_probability,
            confidence=output.confidence,
            model_version=output.model_version,
            features_used=features,
            feature_contributions=output.feature_contributions,
            inference_latency_ms=latency_ms,
        )
