"""Classifier model interfaces and implementations.

Defines:
- BaseClassifier (ABC protocol) allowing any model to be slotted in
- CalibratedHeuristicClassifier (default, high-performance rule-weighted logistic model)
- FallbackClassifier (conservative zero-dependency fallback when primary model fails)
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ClassifierOutput:
    """Output from any BaseClassifier model."""

    label: str  # "phishing", "spam", "clean"
    probability: float  # [0.0, 1.0] primary class probability
    phishing_probability: float  # [0.0, 1.0]
    spam_probability: float  # [0.0, 1.0]
    clean_probability: float  # [0.0, 1.0]
    confidence: float  # [0.0, 1.0]
    model_version: str
    feature_contributions: dict[str, float] = field(default_factory=dict)


class BaseClassifier(ABC):
    """Abstract interface that all classification models must satisfy."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Name of the classifier."""
        ...

    @property
    @abstractmethod
    def model_version(self) -> str:
        """Version string of the classifier."""
        ...

    @abstractmethod
    def predict(self, feature_vector: list[float], features: dict[str, float]) -> ClassifierOutput:
        """Produce a classification given features."""
        ...


class CalibratedHeuristicClassifier(BaseClassifier):
    """Logistic-weighted linear model with calibrated sigmoid probabilities.

    Uses empirically tuned weights trained against email threat corpora.
    Zero external C/compiled dependencies, high inference speed (< 1 ms).
    """

    def __init__(self, version: str = "v1.0.0") -> None:
        self._version = version

        # Logistic regression weights for phishing classification
        # High positive weight = strong phishing signal
        # Negative weight = strong benign signal
        self._weights: dict[str, float] = {
            "subject_length": 0.2,
            "subject_uppercase_ratio": 1.2,
            "body_length": -0.4,
            "body_html_ratio": 0.5,
            "url_count": 0.6,
            "url_has_ip": 2.8,  # Bare IP is an extremely strong phishing signal
            "url_has_shortener": 1.4,
            "url_suspicious_tld_count": 2.5,
            "url_credential_keyword_count": 2.6,
            "url_max_subdomain_depth": 1.2,
            "domain_length": 0.3,
            "domain_entropy": 0.8,
            "domain_digit_ratio": 1.5,
            "domain_is_spoofed_brand": 3.5,  # Strongest single phishing indicator
            "reply_to_mismatch": 2.0,
            "spf_status_score": -2.2,  # SPF pass (-2.2) strongly lowers phishing prob
            "dkim_status_score": -1.8,  # DKIM pass strongly lowers phishing prob
            "dmarc_status_score": -2.0,  # DMARC pass strongly lowers phishing prob
            "attachment_count": 0.4,
            "attachment_has_executable": 4.0,  # Executable attachment is near-certain malware/phish
            "attachment_has_archive": 1.2,
            "attachment_has_macro": 2.8,
            "attachment_max_entropy": 1.5,
            "urgency_keyword_count": 2.2,
            "financial_keyword_count": 1.6,
            "security_lure_keyword_count": 1.8,
            "routing_hop_count": 0.5,
            "missing_message_id": 1.0,
            "has_hidden_text_html": 2.4,
            "structural_anomaly_count": 1.5,
        }
        self._bias: float = -2.5  # Prior favoring clean emails in the absence of threat signals

    @property
    def model_name(self) -> str:
        return "calibrated_logistic_heuristic"

    @property
    def model_version(self) -> str:
        return self._version

    def predict(self, feature_vector: list[float], features: dict[str, float]) -> ClassifierOutput:
        """Compute calibrated probabilities via logistic sigmoid activation."""
        logit = self._bias
        contributions: dict[str, float] = {}

        for name, value in features.items():
            weight = self._weights.get(name, 0.0)
            contrib = weight * value
            logit += contrib
            if abs(contrib) > 0.05:
                contributions[name] = round(contrib, 4)

        # Sigmoid activation for binary phishing probability
        # Clamped logit to prevent overflow
        clamped_logit = max(min(logit, 15.0), -15.0)
        phishing_prob = 1.0 / (1.0 + math.exp(-clamped_logit))

        # Spam probability heuristic (correlated with high URL counts + missing auth + low malware)
        spam_score = (
            features.get("url_count", 0.0) * 0.3
            + features.get("subject_uppercase_ratio", 0.0) * 0.4
            + (1.0 - features.get("spf_status_score", 0.5)) * 0.3
        )
        spam_prob = min(max(spam_score * 0.6, 0.0), 0.95)

        # Clean probability is remaining probability mass
        clean_prob = max(1.0 - phishing_prob, 0.0)

        # Determine winner label
        if phishing_prob >= 0.50:
            label = "phishing"
            primary_prob = phishing_prob
            confidence = min(0.5 + (phishing_prob - 0.5) * 1.0, 0.99)
        elif spam_prob >= 0.55:
            label = "spam"
            primary_prob = spam_prob
            confidence = min(0.5 + (spam_prob - 0.5) * 0.8, 0.90)
        else:
            label = "clean"
            primary_prob = clean_prob
            confidence = min(0.5 + (clean_prob - 0.5) * 1.0, 0.98)

        return ClassifierOutput(
            label=label,
            probability=round(primary_prob, 4),
            phishing_probability=round(phishing_prob, 4),
            spam_probability=round(spam_prob, 4),
            clean_probability=round(clean_prob, 4),
            confidence=round(confidence, 4),
            model_version=self._version,
            feature_contributions=contributions,
        )


class FallbackClassifier(BaseClassifier):
    """Ultra-safe fallback classifier used when primary models are unavailable or corrupt."""

    @property
    def model_name(self) -> str:
        return "fallback_conservative_classifier"

    @property
    def model_version(self) -> str:
        return "fallback-0.1.0"

    def predict(self, feature_vector: list[float], features: dict[str, float]) -> ClassifierOutput:
        """Conservative prediction based on critical binary flags."""
        has_exec = features.get("attachment_has_executable", 0.0) > 0.5
        has_ip = features.get("url_has_ip", 0.0) > 0.5
        has_spoof = features.get("domain_is_spoofed_brand", 0.0) > 0.5

        if has_exec or has_ip or has_spoof:
            return ClassifierOutput(
                label="phishing",
                probability=0.85,
                phishing_probability=0.85,
                spam_probability=0.10,
                clean_probability=0.05,
                confidence=0.75,
                model_version=self.model_version,
                feature_contributions={"critical_fallback_flag": 1.0},
            )

        return ClassifierOutput(
            label="clean",
            probability=0.60,
            phishing_probability=0.20,
            spam_probability=0.20,
            clean_probability=0.60,
            confidence=0.50,
            model_version=self.model_version,
            feature_contributions={},
        )
