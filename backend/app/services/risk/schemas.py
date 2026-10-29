"""Pydantic schemas and data models for the Risk Engine.

Defines the authoritative input and output contracts for risk evaluation:
- RiskAssessment: The final comprehensive evaluation output.
- ThreatEvidenceItem: Explainable audit item detailing evidence contribution.
- RiskSubscores: Normalized component subscores (0.0 to 100.0).
- ThreatIntelSignal: Standardized external/internal threat intelligence findings.
- EngineSource: Taxonomy of signal-producing analysis engines.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import (
    AnalysisVerdict,
    AttackType,
    ReputationVerdict,
    RiskLevel,
    ThreatCategory,
    ThreatSeverity,
)


class EngineSource(StrEnum):
    """Originating engine or pipeline stage producing signals."""

    SECURITY_ENGINE = "security_engine"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    ML_ENGINE = "ml_engine"
    GROQ_LLM = "groq_llm"
    THREAT_INTEL = "threat_intel"


class ThreatEvidenceItem(BaseModel):
    """Explainable evidence item connecting a concrete finding to the risk decision."""

    model_config = ConfigDict(frozen=True)

    source: EngineSource = Field(description="Engine that identified this finding")
    factor_name: str = Field(description="Canonical factor identifier, e.g. 'auth_spf_fail'")
    title: str = Field(description="Human-readable title of the indicator")
    score_contribution: float = Field(
        ge=0.0,
        le=100.0,
        description="Individual score impact before composite weighting",
    )
    severity: ThreatSeverity = Field(description="Severity tier of the finding")
    description: str = Field(description="Technical explanation of the risk indicator")
    indicator_value: str | None = Field(
        default=None,
        description="Observed IOC value (e.g. domain, IP, hash, URL) if applicable",
    )
    evidence_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw forensic telemetry parameters supporting this finding",
    )


class RiskSubscores(BaseModel):
    """Normalized subscores for each analysis dimension (0.0 to 100.0)."""

    model_config = ConfigDict(frozen=True)

    security: float = Field(
        ge=0.0,
        le=100.0,
        description="Deterministic security findings (headers, auth, URL, domain, attachment)",
    )
    behavioral: float = Field(
        ge=0.0,
        le=100.0,
        description="Behavioral heuristics (urgency, evasion, hidden text, deceptive links)",
    )
    ml: float = Field(
        ge=0.0,
        le=100.0,
        description="Machine learning classification probability score",
    )
    llm: float = Field(
        ge=0.0,
        le=100.0,
        description="Groq semantic intent and social engineering assessment score",
    )
    threat_intel: float = Field(
        ge=0.0,
        le=100.0,
        description="External/internal reputation and IOC intelligence score",
    )


class ThreatIntelSignal(BaseModel):
    """Structured threat intelligence indicator match passed into the Risk Engine."""

    model_config = ConfigDict(frozen=True)

    indicator_type: str = Field(
        description="Type: 'domain', 'ip', 'url', 'hash_sha256', 'hash_md5'"
    )
    indicator_value: str = Field(description="Specific IOC value queried")
    provider: str = Field(description="Threat intelligence source (e.g. VirusTotal, AbuseIPDB)")
    verdict: ReputationVerdict = Field(
        default=ReputationVerdict.UNKNOWN,
        description="Aggregated provider verdict (CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN)",
    )
    threat_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Normalized threat reputation score (0.0=benign, 100.0=malicious)",
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Provider assessment confidence",
    )
    tags: list[str] = Field(
        default_factory=list, description="Threat tags, malware families, actors"
    )
    details: dict[str, Any] = Field(default_factory=dict, description="Vendor enrichment data")


class RiskAssessment(BaseModel):
    """Authoritative composite risk assessment produced exclusively by the Risk Engine.

    Every final decision is documented, explainable, and traceable back to concrete
    underlying threat signals and configured policy parameters.
    """

    model_config = ConfigDict(frozen=True)

    risk_score: float = Field(
        ge=0.0,
        le=100.0,
        description="Authoritative composite risk score (0.0 to 100.0)",
    )
    severity: ThreatSeverity = Field(
        description="Final assigned threat severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)",
    )
    risk_level: RiskLevel = Field(
        description="Categorical risk tier (SAFE, LOW, MEDIUM, HIGH, CRITICAL)",
    )
    verdict: AnalysisVerdict = Field(
        description="Automated verdict (CLEAN, SUSPICIOUS, MALICIOUS, QUARANTINE, BLOCK)",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Mathematically aggregated confidence in the risk assessment (0.0 to 1.0)",
    )
    classification: ThreatCategory = Field(
        description="Primary threat category classification (e.g. PHISHING, MALWARE, BEC)",
    )
    attack_type: AttackType = Field(
        description="Specific attack vector or methodology detected",
    )
    signals: list[NormalizedThreatSignal] = Field(
        default_factory=list,
        description="Complete list of all contributing threat signals",
    )
    evidence: list[ThreatEvidenceItem] = Field(
        default_factory=list,
        description="Itemized, explainable evidence contributing to this decision",
    )
    recommendation: str = Field(
        description="Specific actionable operational recommendation (e.g. 'quarantine', 'block')",
    )
    engine_version: str = Field(
        description="Version identifier of the Risk Engine algorithm",
    )
    subscores: RiskSubscores = Field(
        description="Breakdown of normalized subscores per detection dimension",
    )
    weights_applied: dict[str, float] = Field(
        description="Effective normalized weights applied to active engine components",
    )
    policy_name: str = Field(
        description="Name of the evaluated RiskPolicy configuration",
    )
    hard_floor_applied: bool = Field(
        default=False,
        description="True if a hard security invariant prevented score downgrading",
    )
    hard_floor_reason: str | None = Field(
        default=None,
        description="Forensic explanation of hard floor enforcement if triggered",
    )
    rationale: str = Field(
        description="Human-readable SOC narrative explaining why this decision was reached",
    )
    assessed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of risk assessment completion",
    )
