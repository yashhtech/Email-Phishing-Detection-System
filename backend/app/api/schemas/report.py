"""Pydantic schemas for the Security Analysis Reporting module.

Defines the structure for comprehensive, executive-ready analysis reports.
Ensures zero exposure of secrets, internal API keys, or raw provider tokens.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ReportEmailMetadata(BaseModel):
    """Forensic email message metadata."""

    model_config = ConfigDict(from_attributes=True)

    email_id: str
    message_id: str | None = None
    from_address: str
    from_domain: str | None = None
    to_addresses: list[str] = Field(default_factory=list)
    cc_addresses: list[str] = Field(default_factory=list)
    reply_to: str | None = None
    subject: str | None = None
    received_at: datetime
    has_attachments: bool = False
    attachment_count: int = 0
    url_count: int = 0
    # Authentication status summary
    spf_status: str | None = None
    dkim_status: str | None = None
    dmarc_status: str | None = None
    return_path: str | None = None


class ReportRiskScore(BaseModel):
    """Authoritative composite risk score and factor subscores."""

    model_config = ConfigDict(from_attributes=True)

    overall_risk_score: int
    risk_level: str  # critical, high, medium, low, safe
    composite_score: int
    scoring_version: str = "1.0"
    spf_subscore: float = 0.0
    dkim_subscore: float = 0.0
    dmarc_subscore: float = 0.0
    ml_subscore: float = 0.0
    url_subscore: float = 0.0
    attachment_subscore: float = 0.0
    sender_reputation_subscore: float = 0.0
    factor_breakdown: list[dict[str, Any]] | None = None


class ReportClassification(BaseModel):
    """Categorical security verdict and classification outcome."""

    model_config = ConfigDict(from_attributes=True)

    verdict: str  # clean, suspicious, malicious, quarantine, block
    status: str  # completed, failed, etc.
    primary_attack_type: str  # spear_phishing, credential_harvesting, etc.
    severity: str  # critical, high, medium, low, info
    confidence: float


class ReportSecuritySignal(BaseModel):
    """Deterministic security signal captured during multi-engine evaluation."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    signal_type: str
    category: str
    severity: str
    attack_type: str
    confidence: float
    source: str
    title: str
    description: str
    indicator_value: str | None = None


class ReportMLAnalysis(BaseModel):
    """Machine learning model classification breakdown."""

    model_config = ConfigDict(from_attributes=True)

    model_name: str
    model_version: str
    classification: str
    confidence: float
    phishing_probability: float
    spam_probability: float
    malware_probability: float
    latency_ms: int | None = None


class ReportGroqAnalysis(BaseModel):
    """Groq LLM semantic reasoning and contextual narrative (sanitized)."""

    model_config = ConfigDict(from_attributes=True)

    model_name: str
    prompt_version: str
    threat_narrative: str
    executive_summary: str | None = None
    recommended_action: str
    reasoning: str | None = None
    extracted_iocs: list[dict[str, Any]] = Field(default_factory=list)
    safety_passed: bool = True
    confidence_score: float
    latency_ms: int | None = None


class ReportThreatIntelligence(BaseModel):
    """External reputation intelligence findings (sanitized, no internal API keys)."""

    model_config = ConfigDict(from_attributes=True)

    indicator_type: str
    indicator_value: str
    provider: str
    reputation: str
    threat_score: int | None = None
    tags: list[str] = Field(default_factory=list)
    last_checked_at: datetime


class ReportEvidenceItem(BaseModel):
    """Forensic evidence item detailing findings and risk rationale."""

    model_config = ConfigDict(from_attributes=True)

    title: str
    severity: str
    source: str
    category: str
    attack_type: str
    description: str
    indicator_value: str | None = None
    confidence: float
    why_it_matters: str


class ReportTimestamps(BaseModel):
    """Chronological event timestamps across lifecycle."""

    email_received_at: datetime | None = None
    analysis_started_at: datetime | None = None
    analysis_completed_at: datetime | None = None
    report_generated_at: datetime
    duration_ms: int | None = None


class AnalysisReportResponse(BaseModel):
    """Complete, authoritative email threat analysis report."""

    model_config = ConfigDict(from_attributes=True)

    report_id: uuid.UUID
    analysis_id: uuid.UUID
    org_id: uuid.UUID
    org_name: str | None = None
    engine_version: str = "1.0.0"
    scoring_version: str = "1.0"
    classification: ReportClassification
    risk_score: ReportRiskScore
    email_metadata: ReportEmailMetadata
    security_signals: list[ReportSecuritySignal]
    ml_analysis: ReportMLAnalysis | None = None
    groq_analysis: ReportGroqAnalysis | None = None
    threat_intelligence: list[ReportThreatIntelligence] = Field(default_factory=list)
    evidence: list[ReportEvidenceItem] = Field(default_factory=list)
    timestamps: ReportTimestamps
    generated_by: str
    confidentiality: str = "CONFIDENTIAL - RESTRICTED SECURITY INCIDENT REPORT"
