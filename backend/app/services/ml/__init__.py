"""Machine learning classification engine package."""

from app.services.ml.classifier import (
    BaseClassifier,
    CalibratedHeuristicClassifier,
    ClassifierOutput,
    FallbackClassifier,
)
from app.services.ml.evaluation import (
    BinaryConfusionMatrix,
    ClassificationMetrics,
    ModelEvaluator,
)
from app.services.ml.feature_extractor import (
    FEATURE_NAMES,
    FeatureExtractionResult,
    FeatureExtractor,
)
from app.services.ml.inference import (
    MLInferenceResult,
    MLInferenceService,
)
from app.services.ml.model_registry import ModelRegistry

__all__ = [
    "FEATURE_NAMES",
    "BaseClassifier",
    "BinaryConfusionMatrix",
    "CalibratedHeuristicClassifier",
    "ClassificationMetrics",
    "ClassifierOutput",
    "FallbackClassifier",
    "FeatureExtractionResult",
    "FeatureExtractor",
    "MLInferenceResult",
    "MLInferenceService",
    "ModelEvaluator",
    "ModelRegistry",
]
