"""Pydantic schemas for the production Security Operations Dashboard."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Metric Models
# ---------------------------------------------------------------------------


class LLMUsageMetric(BaseModel):
    """Aggregated Groq LLM telemetry."""

    total_calls: int = Field(default=0, description="Total times LLM was invoked or evaluated")
    analyzed_calls: int = Field(default=0, description="Semantic deep analyses completed by LLM")
    skipped_calls: int = Field(
        default=0, description="Calls safely bypassed when preliminary risk < threshold"
    )
    average_latency_ms: float = Field(
        default=0.0, description="Average LLM roundtrip latency in ms"
    )
    models_breakdown: dict[str, int] = Field(
        default_factory=dict, description="Invocations per model version"
    )


class DashboardMetricsResponse(BaseModel):
    """Complete authoritative metric card values directly computed from PostgreSQL."""

    total_emails_analyzed: int = Field(
        default=0, description="Total emails processed through pipeline"
    )
    threats_detected: int = Field(
        default=0, description="Total threat emails identified (malicious or suspicious)"
    )
    high_risk_emails: int = Field(default=0, description="Emails in high risk tier (score 70-89)")
    critical_threats: int = Field(
        default=0, description="Emails in critical risk tier (score 90-100)"
    )
    phishing_count: int = Field(
        default=0, description="Identified phishing signals across all analyzers"
    )
    bec_count: int = Field(
        default=0, description="Identified Business Email Compromise / Impersonation signals"
    )
    credential_theft_count: int = Field(
        default=0, description="Credential harvesting / login lures identified"
    )
    malware_related_events: int = Field(
        default=0, description="Malicious attachment or payload signals detected"
    )
    average_risk_score: float = Field(default=0.0, description="Mean composite risk score (0-100)")
    analysis_success_rate: float = Field(
        default=100.0, description="Percentage of pipeline jobs completed without error"
    )
    llm_usage: LLMUsageMetric = Field(
        default_factory=LLMUsageMetric, description="Groq LLM telemetry"
    )
    average_analysis_latency_ms: float = Field(
        default=0.0, description="Mean end-to-end pipeline execution time in ms"
    )


# ---------------------------------------------------------------------------
# Chart Data Models
# ---------------------------------------------------------------------------


class ThreatTimelinePoint(BaseModel):
    """Daily threat breakdown for time-series charts."""

    date: str = Field(description="ISO Date (YYYY-MM-DD)")
    clean: int = Field(default=0, description="Clean emails on this day")
    suspicious: int = Field(default=0, description="Suspicious emails on this day")
    malicious: int = Field(default=0, description="Malicious emails on this day")
    total: int = Field(default=0, description="Total volume on this day")


class RiskDistributionBucket(BaseModel):
    """Risk score histogram bucket."""

    tier: str = Field(description="Bucket label e.g. 'Safe (0-19)'")
    count: int = Field(default=0, description="Number of emails in this bucket")
    color: str = Field(description="Design system token color")


class AttackTypeItem(BaseModel):
    """Attack vector methodology distribution item."""

    attack_type: str = Field(description="Human readable attack methodology")
    count: int = Field(default=0, description="Total occurrences observed")
    percentage: float = Field(default=0.0, description="Percentage of total attack signals")


class SeverityDistributionItem(BaseModel):
    """Threat severity distribution item."""

    severity: str = Field(
        description="Severity label e.g. 'critical', 'high', 'medium', 'low', 'info'"
    )
    count: int = Field(default=0, description="Count of signals with this severity")
    color: str = Field(description="Design token color")


class LatencyDistributionBucket(BaseModel):
    """Pipeline processing time histogram bucket."""

    bucket: str = Field(description="Latency bracket e.g. '< 500ms', '500ms-1s'")
    count: int = Field(default=0, description="Analyses completing within this window")


class DetectionTrendPoint(BaseModel):
    """Trend line point tracking threat detection rate over time."""

    date: str = Field(description="ISO Date (YYYY-MM-DD)")
    detection_rate_pct: float = Field(default=0.0, description="Threat percentage of total volume")
    volume: int = Field(default=0, description="Total emails processed")


class RecentThreatItem(BaseModel):
    """Individual high/critical threat event for forensic inspection table."""

    analysis_id: str
    email_id: str
    subject: str
    from_address: str
    from_domain: str
    risk_score: int
    risk_level: str
    verdict: str
    attack_type: str
    category: str
    received_at: str
    has_attachments: bool


class DashboardChartsResponse(BaseModel):
    """Composite payload powering all 8 production dashboard visualizations."""

    threats_over_time: list[ThreatTimelinePoint] = Field(default_factory=list)
    risk_distribution: list[RiskDistributionBucket] = Field(default_factory=list)
    attack_type_distribution: list[AttackTypeItem] = Field(default_factory=list)
    severity_distribution: list[SeverityDistributionItem] = Field(default_factory=list)
    processing_time_distribution: list[LatencyDistributionBucket] = Field(default_factory=list)
    llm_usage: LLMUsageMetric = Field(default_factory=LLMUsageMetric)
    detection_trends: list[DetectionTrendPoint] = Field(default_factory=list)
    recent_threats: list[RecentThreatItem] = Field(default_factory=list)
