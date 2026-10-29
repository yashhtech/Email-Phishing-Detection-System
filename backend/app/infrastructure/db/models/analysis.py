"""Security analysis models including pipeline execution, threat signals, ML, LLM, risk scores, TI, and events."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.db.models.base_model import BaseModel, SoftDeleteMixin
from app.infrastructure.db.models.enums import (
    AnalysisStatus,
    AnalysisVerdict,
    AttackType,
    ReputationVerdict,
    RiskLevel,
    ThreatCategory,
    ThreatSeverity,
)

if TYPE_CHECKING:
    from app.infrastructure.db.models.email import Email
    from app.infrastructure.db.models.organization import Organization


class Analysis(BaseModel, SoftDeleteMixin):
    """Orchestrated email analysis instance."""

    __tablename__ = "analyses"

    email_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("emails.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
        comment="Associated email ID (1:1)",
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Associated organization tenant ID",
    )
    status: Mapped[AnalysisStatus] = mapped_column(
        Enum(AnalysisStatus, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        default=AnalysisStatus.QUEUED,
        nullable=False,
        index=True,
        comment="Pipeline lifecycle state",
    )
    verdict: Mapped[AnalysisVerdict | None] = mapped_column(
        Enum(AnalysisVerdict, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=True,
        index=True,
        comment="Final security verdict",
    )
    overall_risk_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
        comment="Composite score 0-100",
    )
    risk_level: Mapped[RiskLevel | None] = mapped_column(
        Enum(RiskLevel, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=True,
        index=True,
        comment="Categorical risk classification",
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Analysis execution start timestamp",
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Analysis execution completion timestamp",
    )
    duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Execution elapsed duration in milliseconds",
    )
    retry_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Number of times analysis was retried",
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Failure diagnosis message if analysis failed",
    )
    model_versions: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="Snapshot of model versions used during analysis",
    )

    # Relationships
    email: Mapped[Email] = relationship(
        "Email",
        back_populates="analysis",
    )
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="analyses",
    )
    risk_score: Mapped[RiskScore | None] = relationship(
        "RiskScore",
        back_populates="analysis",
        uselist=False,
        cascade="all, delete-orphan",
    )
    ml_prediction: Mapped[MLPrediction | None] = relationship(
        "MLPrediction",
        back_populates="analysis",
        uselist=False,
        cascade="all, delete-orphan",
    )
    llm_analysis: Mapped[LLMAnalysis | None] = relationship(
        "LLMAnalysis",
        back_populates="analysis",
        uselist=False,
        cascade="all, delete-orphan",
    )
    threat_signals: Mapped[list[ThreatSignal]] = relationship(
        "ThreatSignal",
        back_populates="analysis",
        cascade="all, delete-orphan",
    )
    threat_intel_results: Mapped[list[ThreatIntelligenceResult]] = relationship(
        "ThreatIntelligenceResult",
        back_populates="analysis",
        cascade="all, delete-orphan",
    )
    events: Mapped[list[AnalysisEvent]] = relationship(
        "AnalysisEvent",
        back_populates="analysis",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_analyses_org_completed", "org_id", "completed_at"),
        Index("ix_analyses_org_risk_score", "org_id", "overall_risk_score"),
        Index("ix_analyses_org_status", "org_id", "status"),
        Index("ix_analyses_verdict_completed", "verdict", "completed_at"),
        Index("ix_analyses_risk_level_completed", "risk_level", "completed_at"),
        Index("ix_analyses_org_created_at", "org_id", "created_at"),
        Index("ix_analyses_org_risk_level_created", "org_id", "risk_level", "created_at"),
        Index("ix_analyses_org_verdict_created", "org_id", "verdict", "created_at"),
    )


class ThreatSignal(BaseModel):
    """Specific security indicator or threat finding discovered during analysis."""

    __tablename__ = "threat_signals"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("analyses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Associated analysis ID",
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Associated organization tenant ID",
    )
    signal_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Detection rule / heuristic type",
    )
    category: Mapped[ThreatCategory] = mapped_column(
        Enum(ThreatCategory, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
        comment="Threat taxonomy category",
    )
    severity: Mapped[ThreatSeverity] = mapped_column(
        Enum(ThreatSeverity, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
        comment="Finding severity level",
    )
    attack_type: Mapped[AttackType] = mapped_column(
        Enum(AttackType, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        default=AttackType.UNKNOWN,
        nullable=False,
        index=True,
        comment="Identified attack vector or methodology",
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        index=True,
        comment="Detection confidence (0.0 to 1.0)",
    )
    source_engine: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Engine that produced finding (header, ml, llm, url, attachment)",
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Brief finding title",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Detailed technical explanation",
    )
    indicator_value: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        index=True,
        comment="Associated IOC value (IP, domain, hash, URL) if applicable",
    )
    raw_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="Forensic telemetry context and matching patterns",
    )

    # Relationship
    analysis: Mapped[Analysis] = relationship(
        "Analysis",
        back_populates="threat_signals",
    )

    __table_args__ = (
        Index("ix_threat_signals_severity_category_attack", "severity", "category", "attack_type"),
        Index("ix_threat_signals_org_severity_created", "org_id", "severity", "created_at"),
        Index("ix_threat_signals_analysis_severity", "analysis_id", "severity"),
        Index("ix_threat_signals_analysis_attack", "analysis_id", "attack_type"),
    )


class MLPrediction(BaseModel):
    """Machine learning classification model output."""

    __tablename__ = "ml_predictions"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("analyses.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
        comment="Associated analysis ID (1:1)",
    )
    model_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Classifier model identifier",
    )
    model_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Model artifact version tag",
    )
    prediction_label: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Predicted class (e.g. phishing, clean, spam)",
    )
    confidence_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        index=True,
        comment="Model confidence (0.0 to 1.0)",
    )
    phishing_probability: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        index=True,
        comment="Calibrated probability of phishing (0.0 to 1.0)",
    )
    spam_probability: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        comment="Calibrated probability of spam (0.0 to 1.0)",
    )
    malware_probability: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        comment="Calibrated probability of malware (0.0 to 1.0)",
    )
    feature_weights: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="SHAP or feature importance values for explainability",
    )
    latency_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Inference time in milliseconds",
    )

    # Relationship
    analysis: Mapped[Analysis] = relationship(
        "Analysis",
        back_populates="ml_prediction",
    )


class LLMAnalysis(BaseModel):
    """Structured LLM threat narrative and contextual analysis."""

    __tablename__ = "llm_analyses"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("analyses.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
        comment="Associated analysis ID (1:1)",
    )
    model_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="LLM model (e.g. llama-3.3-70b-versatile via Groq)",
    )
    prompt_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Version of prompt template used",
    )
    threat_narrative: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Comprehensive analytical narrative of the threat scenario",
    )
    executive_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Concise summary for non-technical stakeholders",
    )
    recommended_action: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Action recommendation (e.g. quarantine, allow, alert_admin)",
    )
    reasoning: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Step-by-step reasoning steps leading to conclusion",
    )
    extracted_iocs: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="Structured list of extracted indicators of compromise",
    )
    confidence_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Self-reported LLM confidence (0.0 to 1.0)",
    )
    token_usage: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="Prompt, completion, and total token usage metrics",
    )
    safety_passed: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="True if output passed safety gateway validation",
    )
    latency_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Inference API roundtrip in milliseconds",
    )

    # Relationship
    analysis: Mapped[Analysis] = relationship(
        "Analysis",
        back_populates="llm_analysis",
    )


class RiskScore(BaseModel):
    """Persisted authoritative composite risk score and factor subscores."""

    __tablename__ = "risk_scores"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("analyses.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
        comment="Associated analysis ID (1:1)",
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Associated organization tenant ID",
    )
    composite_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
        comment="Final calculated risk score (0 to 100)",
    )
    risk_level: Mapped[RiskLevel] = mapped_column(
        Enum(RiskLevel, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
        comment="Calculated categorical risk level",
    )
    spf_subscore: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        comment="SPF factor contribution",
    )
    dkim_subscore: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        comment="DKIM factor contribution",
    )
    dmarc_subscore: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        comment="DMARC factor contribution",
    )
    ml_subscore: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        comment="ML model factor contribution",
    )
    url_subscore: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        comment="URL reputation factor contribution",
    )
    attachment_subscore: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        comment="Attachment threat factor contribution",
    )
    sender_reputation_subscore: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        comment="Domain/sender age and reputation factor contribution",
    )
    factor_breakdown: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="Detailed weight and description for each factor",
    )
    scoring_version: Mapped[str] = mapped_column(
        String(20),
        default="1.0",
        nullable=False,
        comment="Version of scoring algorithm used",
    )

    # Relationship
    analysis: Mapped[Analysis] = relationship(
        "Analysis",
        back_populates="risk_score",
    )

    __table_args__ = (
        Index("ix_risk_scores_org_score", "org_id", "composite_score"),
        Index("ix_risk_scores_org_level_created", "org_id", "risk_level", "created_at"),
        Index("ix_risk_scores_composite_level", "composite_score", "risk_level"),
    )


class ThreatIntelligenceResult(BaseModel):
    """External threat intelligence query outcome cached and linked to analysis."""

    __tablename__ = "threat_intelligence_results"

    analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("analyses.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Optional linking to the specific analysis that triggered check",
    )
    indicator_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Type of indicator (domain, ip, url, hash_sha256, hash_md5)",
    )
    indicator_value: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        index=True,
        comment="Raw value of indicator",
    )
    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Intel source e.g. 'virustotal', 'whois', 'internal_db'",
    )
    reputation_verdict: Mapped[ReputationVerdict] = mapped_column(
        Enum(ReputationVerdict, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        default=ReputationVerdict.UNKNOWN,
        nullable=False,
        index=True,
        comment="Aggregated vendor verdict",
    )
    threat_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Provider reputation score (0-100 where higher is more malicious)",
    )
    tags: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="Vendor threat tags and malware family labels",
    )
    raw_response: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="Raw payload returned from provider API",
    )
    last_checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Timestamp when query was performed",
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Cache expiration timestamp for TTL invalidation",
    )

    # Relationship
    analysis: Mapped[Analysis | None] = relationship(
        "Analysis",
        back_populates="threat_intel_results",
    )

    __table_args__ = (
        Index("ix_ti_type_value", "indicator_type", "indicator_value"),
        Index("ix_ti_provider_verdict", "provider", "reputation_verdict"),
        Index("ix_ti_expires_at", "expires_at"),
    )


class AnalysisEvent(BaseModel):
    """Pipeline milestone / stage execution event for real-time tracking."""

    __tablename__ = "analysis_events"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("analyses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Parent analysis reference",
    )
    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Event code e.g. 'stage_completed', 'signal_detected'",
    )
    stage: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Pipeline stage (headers, urls, attachments, ml, llm, scoring)",
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Stage execution status (started, completed, failed, skipped)",
    )
    message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Diagnostic or status message",
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="Stage output metadata or interim findings",
    )
    duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Stage duration in milliseconds",
    )

    # Relationship
    analysis: Mapped[Analysis] = relationship(
        "Analysis",
        back_populates="events",
    )

    __table_args__ = (Index("ix_analysis_events_analysis_stage", "analysis_id", "stage"),)
