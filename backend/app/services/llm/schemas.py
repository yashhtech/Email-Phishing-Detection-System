"""Pydantic schemas for LLM threat analysis inputs and outputs.

Validates:
- Structured JSON output returned by LLM models
- Provider telemetry and metadata (latency, status, model, provider, tokens)
- Intent classification, psychological triggers, and recommendations
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class LLMIntentClassification(StrEnum):
    """Categorized threat intent identified by semantic analysis."""

    PHISHING = "phishing"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    BUSINESS_EMAIL_COMPROMISE = "business_email_compromise"
    EXTORTION = "extortion"
    SOCIAL_ENGINEERING = "social_engineering"
    SPAM = "spam"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class LLMAnalysisResponse(BaseModel):
    """Strictly validated structured response required from the LLM provider."""

    classification: LLMIntentClassification = Field(
        description="Primary intent classification of the email"
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Self-reported confidence in the semantic assessment (0.0 to 1.0)",
    )
    is_phishing_intent: bool = Field(
        description="True if email demonstrates deceptive/phishing intent"
    )
    is_bec_intent: bool = Field(
        description="True if email demonstrates Business Email Compromise / executive fraud"
    )
    is_credential_request: bool = Field(
        description="True if email solicits credentials, passwords, or authentication factors"
    )
    is_payment_request: bool = Field(
        description="True if email solicits wire transfer, gift card, or payment manipulation"
    )
    social_engineering_tactics: list[str] = Field(
        default_factory=list,
        description="Specific tactics used (e.g. urgency, authority, fear, curiosity, scarcity)",
    )
    impersonation_target: str | None = Field(
        default=None,
        description="Specific individual or organization impersonated, if any",
    )
    threat_narrative: str = Field(
        min_length=10,
        description="Comprehensive analytical narrative detailing why the email is or is not threatening",
    )
    executive_summary: str = Field(
        min_length=10,
        description="Concise 1-2 sentence non-technical summary for stakeholders",
    )
    recommended_action: str = Field(
        description="Recommended action (e.g., quarantine, delete, allow, report_phishing)",
    )
    evidence_quotes: list[str] = Field(
        default_factory=list,
        description="Exact substrings from the untrusted email body demonstrating malicious intent",
    )


class LLMResult(BaseModel):
    """Complete metadata and analytical result returned by the LLM service."""

    provider: str = Field(default="groq", description="LLM provider name")
    model: str = Field(description="LLM model identifier")
    status: str = Field(description="'success', 'fallback', 'timeout', 'api_error', 'unconfigured'")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    classification: str = Field(description="Intent classification label")
    latency_ms: float = Field(ge=0.0, description="Inference latency in milliseconds")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    analysis: LLMAnalysisResponse | None = Field(
        default=None, description="Structured analysis output if successful"
    )
    error_message: str | None = Field(default=None, description="Sanitized failure reason if any")
    token_usage: dict[str, int] = Field(
        default_factory=dict, description="Tokens used (prompt, completion, total)"
    )
