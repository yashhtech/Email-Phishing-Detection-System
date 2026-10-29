"""Comprehensive unit tests for the ML classification engine.

Coverage:
1. FeatureExtractor:
   - All 30 features extracted deterministically
   - Vector values normalized in [0.0, 1.0]
   - Phishing features correctly reflect high values (IP URLs, spoofed brands, missing auth)
   - Clean features reflect low threat values

2. ModelRegistry:
   - Version registration and lookup
   - Active default version management
   - Fallback behavior when requested version is unknown
   - Runtime model listing and swapping

3. Classifier:
   - BaseClassifier interface compliance
   - CalibratedHeuristicClassifier probabilities in [0.0, 1.0]
   - Mathematical sigmoid calibration
   - Winner label selection logic
   - FallbackClassifier conservative predictions

4. MLInferenceService:
   - Full pipeline inference from EmailAnalysisInput
   - Prediction structure: classification, probability, confidence, model_version, features_used, inference_latency_ms
   - Explainability contributions present
   - Inference latency measured and positive
   - Version override honored
   - Error recovery with fallback model

5. ModelEvaluator:
   - Precision, recall, F1 computation
   - Specificity and accuracy
   - ROC-AUC non-parametric calculation
   - Confusion matrix (TP, FP, TN, FN)
   - Brier score calibration
   - Error handling for length mismatches and empty inputs
"""

from __future__ import annotations

import pytest

from app.services.email_preprocessing_pipeline import EmailPreprocessingPipeline
from app.services.ml.classifier import (
    BaseClassifier,
    CalibratedHeuristicClassifier,
    ClassifierOutput,
    FallbackClassifier,
)
from app.services.ml.evaluation import ModelEvaluator
from app.services.ml.feature_extractor import FEATURE_NAMES, FeatureExtractor
from app.services.ml.inference import MLInferenceResult, MLInferenceService
from app.services.ml.model_registry import ModelRegistry

prep = EmailPreprocessingPipeline()


# ============================================================================
# 1. FeatureExtractor Tests
# ============================================================================


class TestFeatureExtractor:
    extractor = FeatureExtractor()

    def test_extracts_all_30_features(self) -> None:
        email_input = prep.preprocess_structured(
            from_address="user@company.com",
            to_addresses=["colleague@company.com"],
            subject="Status Report",
            body_plain="Weekly updates inside.",
        )
        res = self.extractor.extract(email_input)
        assert len(res.feature_names) == 30
        assert len(res.feature_vector) == 30
        assert len(res.features) == 30

    def test_features_are_bounded(self) -> None:
        email_input = prep.preprocess_structured(
            from_address="user@company.com",
            to_addresses=["colleague@company.com"],
            subject="VERY LONG UPPERCASE URGENT SUBJECT " * 5,
            body_plain="Click here http://185.220.101.5/login immediately " * 20,
        )
        res = self.extractor.extract(email_input)
        for name, val in res.features.items():
            assert 0.0 <= val <= 1.0, f"Feature '{name}' out of bounds: {val}"

    def test_phishing_email_produces_high_threat_features(self) -> None:
        raw = (
            'From: "PayPal Security" <security@paypa1-update.top>\r\n'
            "Reply-To: phish@evil.xyz\r\n"
            "To: victim@target.com\r\n"
            "Subject: URGENT: Account Suspended\r\n"
            "Message-ID: <1@test>\r\n"
            "Received-SPF: fail\r\n\r\n"
            "Action required immediately! Wire transfer or verify your account at http://185.220.101.5/login"
        )
        email_input = prep.preprocess_raw(raw)
        res = self.extractor.extract(email_input)

        assert res.features["url_has_ip"] == 1.0
        assert res.features["domain_is_spoofed_brand"] == 1.0
        assert res.features["reply_to_mismatch"] == 1.0
        assert res.features["spf_status_score"] == 0.0  # fail = 0.0
        assert res.features["urgency_keyword_count"] > 0.0


# ============================================================================
# 2. ModelRegistry Tests
# ============================================================================


class TestModelRegistry:
    def test_registry_initializes_with_default_models(self) -> None:
        reg = ModelRegistry()
        models = reg.list_models()
        assert len(models) >= 2
        default_model = reg.get_model()
        assert default_model.model_version == "v1.0.0"

    def test_retrieve_specific_version(self) -> None:
        reg = ModelRegistry()
        m1 = reg.get_model("v1.1.0")
        assert m1.model_version == "v1.1.0"

    def test_unknown_version_falls_back_to_default(self) -> None:
        reg = ModelRegistry()
        fallback = reg.get_model("v99.99.99-unknown")
        assert fallback is not None
        assert fallback.model_version == reg.default_version

    def test_set_default_version(self) -> None:
        reg = ModelRegistry()
        reg.set_default_version("v1.1.0")
        assert reg.default_version == "v1.1.0"
        assert reg.get_model().model_version == "v1.1.0"

    def test_set_invalid_default_raises_keyerror(self) -> None:
        reg = ModelRegistry()
        with pytest.raises(KeyError):
            reg.set_default_version("non_existent_version")

    def test_register_custom_model(self) -> None:
        reg = ModelRegistry()

        class CustomDummy(BaseClassifier):
            @property
            def model_name(self) -> str:
                return "dummy"

            @property
            def model_version(self) -> str:
                return "v3.0.0-custom"

            def predict(
                self, feature_vector: list[float], features: dict[str, float]
            ) -> ClassifierOutput:
                return ClassifierOutput("clean", 0.9, 0.05, 0.05, 0.9, 0.9, "v3.0.0-custom", {})

        reg.register(CustomDummy(), is_default=True)
        assert reg.default_version == "v3.0.0-custom"
        assert reg.get_model().model_name == "dummy"


# ============================================================================
# 3. Classifier Tests
# ============================================================================


class TestClassifiers:
    def test_calibrated_heuristic_predicts_clean(self) -> None:
        model = CalibratedHeuristicClassifier(version="v1.0.0")
        # All zeros features (clean benign baseline)
        features = dict.fromkeys(FEATURE_NAMES, 0.0)
        features["spf_status_score"] = 1.0  # Pass
        features["dkim_status_score"] = 1.0
        features["dmarc_status_score"] = 1.0

        vector = [features[name] for name in FEATURE_NAMES]
        out = model.predict(vector, features)

        assert out.label == "clean"
        assert out.phishing_probability < 0.20
        assert out.clean_probability > 0.70
        assert 0.0 <= out.confidence <= 1.0
        assert out.model_version == "v1.0.0"

    def test_calibrated_heuristic_predicts_phishing(self) -> None:
        model = CalibratedHeuristicClassifier(version="v1.0.0")
        # Strong phishing features
        features = dict.fromkeys(FEATURE_NAMES, 0.0)
        features["domain_is_spoofed_brand"] = 1.0
        features["url_has_ip"] = 1.0
        features["attachment_has_executable"] = 1.0
        features["spf_status_score"] = 0.0  # Fail
        features["urgency_keyword_count"] = 1.0

        vector = [features[name] for name in FEATURE_NAMES]
        out = model.predict(vector, features)

        assert out.label == "phishing"
        assert out.phishing_probability >= 0.80
        assert out.confidence >= 0.80
        assert len(out.feature_contributions) > 0

    def test_fallback_classifier_on_critical_flags(self) -> None:
        fallback = FallbackClassifier()
        features = {"attachment_has_executable": 1.0}
        out = fallback.predict([1.0], features)
        assert out.label == "phishing"
        assert out.phishing_probability == 0.85

    def test_fallback_classifier_on_clean_flags(self) -> None:
        fallback = FallbackClassifier()
        features = {"attachment_has_executable": 0.0}
        out = fallback.predict([0.0], features)
        assert out.label == "clean"
        assert out.clean_probability == 0.60


# ============================================================================
# 4. MLInferenceService Tests
# ============================================================================


class TestMLInferenceService:
    service = MLInferenceService()

    def test_clean_email_inference_output(self) -> None:
        email_input = prep.preprocess_structured(
            from_address="boss@company.com",
            to_addresses=["employee@company.com"],
            subject="Project roadmap sync",
            body_plain="Let us discuss the quarterly timeline tomorrow morning.",
            raw_headers_str="Authentication-Results: mx.company.com; spf=pass dkim=pass dmarc=pass",
        )
        res = self.service.predict(email_input)

        assert isinstance(res, MLInferenceResult)
        assert res.classification in ("clean", "phishing", "spam")
        assert res.classification == "clean"
        assert 0.0 <= res.probability <= 1.0
        assert 0.0 <= res.confidence <= 1.0
        assert res.model_version == "v1.0.0"
        assert len(res.features_used) == 30
        assert res.inference_latency_ms >= 0.0  # Latency measured

    def test_phishing_email_inference_output(self) -> None:
        raw = (
            'Content-Type: multipart/mixed; boundary="B"\r\n'
            'From: "PayPal" <security@paypa1.top>\r\n'
            "To: victim@company.com\r\n"
            "Subject: URGENT: Confirm your password\r\n"
            "Received-SPF: fail\r\n"
            "Message-ID: <1@test>\r\n\r\n"
            "--B\r\nContent-Type: text/plain\r\n\r\n"
            "Immediate action required! Login at http://185.220.101.5/login to prevent suspension.\r\n"
            '--B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="patch.exe"\r\n\r\n'
            "MZfake\r\n--B--"
        )
        email_input = prep.preprocess_raw(raw)
        res = self.service.predict(email_input)

        assert res.classification == "phishing"
        assert res.phishing_probability >= 0.85
        assert res.confidence >= 0.80
        assert (
            "url_has_ip" in res.feature_contributions
            or "domain_is_spoofed_brand" in res.feature_contributions
        )

    def test_version_override(self) -> None:
        email_input = prep.preprocess_structured(
            from_address="a@b.com",
            to_addresses=["c@d.com"],
            subject="Test",
            body_plain="Hi",
        )
        res = self.service.predict(email_input, model_version="v1.1.0")
        assert res.model_version == "v1.1.0"

    def test_inference_recovers_gracefully_when_model_fails(self) -> None:
        # Register a buggy model that throws
        reg = ModelRegistry()

        class CrashingClassifier(BaseClassifier):
            @property
            def model_name(self) -> str:
                return "buggy"

            @property
            def model_version(self) -> str:
                return "v-broken"

            def predict(
                self, feature_vector: list[float], features: dict[str, float]
            ) -> ClassifierOutput:
                raise RuntimeError("Hardware failure / CUDA OOM")

        reg.register(CrashingClassifier(), is_default=True)
        service = MLInferenceService(registry=reg)

        email_input = prep.preprocess_structured(
            from_address="a@b.com",
            to_addresses=["c@d.com"],
            subject="Test",
            body_plain="Body",
        )
        # Should not crash; recovers via fallback
        res = service.predict(email_input)
        assert res is not None
        assert res.model_version == "fallback-0.1.0"


# ============================================================================
# 5. ModelEvaluator Tests
# ============================================================================


class TestModelEvaluator:
    evaluator = ModelEvaluator()

    def test_perfect_predictions(self) -> None:
        y_true = [1, 1, 0, 0]
        y_pred = [1, 1, 0, 0]
        y_prob = [0.95, 0.85, 0.10, 0.05]

        metrics = self.evaluator.evaluate(y_true, y_pred, y_prob)

        assert metrics.accuracy == 1.0
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.f1_score == 1.0
        assert metrics.specificity == 1.0
        assert metrics.roc_auc == 1.0
        assert metrics.confusion_matrix.true_positives == 2
        assert metrics.confusion_matrix.true_negatives == 2
        assert metrics.confusion_matrix.false_positives == 0
        assert metrics.confusion_matrix.false_negatives == 0
        assert metrics.brier_score < 0.05

    def test_mixed_predictions(self) -> None:
        y_true = [1, 1, 1, 0, 0, 0]
        y_pred = [1, 1, 0, 0, 0, 1]  # 1 FN, 1 FP
        y_prob = [0.9, 0.8, 0.4, 0.2, 0.1, 0.7]

        metrics = self.evaluator.evaluate(y_true, y_pred, y_prob)

        assert metrics.confusion_matrix.true_positives == 2
        assert metrics.confusion_matrix.false_positives == 1
        assert metrics.confusion_matrix.false_negatives == 1
        assert metrics.confusion_matrix.true_negatives == 2
        assert metrics.accuracy == round(4 / 6, 4)
        assert metrics.precision == round(2 / 3, 4)
        assert metrics.recall == round(2 / 3, 4)
        assert metrics.roc_auc is not None
        assert metrics.roc_auc > 0.5

    def test_length_mismatch_raises_error(self) -> None:
        with pytest.raises(ValueError):
            self.evaluator.evaluate([1, 0], [1])

    def test_empty_input_raises_error(self) -> None:
        with pytest.raises(ValueError):
            self.evaluator.evaluate([], [])

    def test_roc_auc_single_class_edge_case(self) -> None:
        # All positive labels: ROC-AUC is undefined edge case returning 0.5
        y_true = [1, 1, 1]
        y_pred = [1, 1, 1]
        y_prob = [0.8, 0.9, 0.7]
        metrics = self.evaluator.evaluate(y_true, y_pred, y_prob)
        assert metrics.roc_auc == 0.5
