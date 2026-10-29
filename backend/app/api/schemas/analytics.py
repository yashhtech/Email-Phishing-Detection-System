"""Pydantic schemas for the Security Analytics module."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DateRangeMeta(BaseModel):
    """Metadata describing the active analytics date filter window."""

    model_config = ConfigDict(from_attributes=True)

    start: datetime = Field(description="Start timestamp in UTC")
    end: datetime = Field(description="End timestamp in UTC")
    preset: str | None = Field(
        default=None, description="Preset identifier e.g. '24h', '7d', '30d', '90d'"
    )
    use_hourly: bool = Field(
        default=False, description="True if trends are grouped by hour instead of day"
    )


class ThreatTrendPoint(BaseModel):
    """Aggregate volume of email analyses by security verdict in a single time bucket."""

    model_config = ConfigDict(from_attributes=True)

    timestamp: datetime = Field(description="Bucket start timestamp")
    total: int = Field(default=0, description="Total analyses in this window")
    clean: int = Field(default=0, description="Clean verdicts count")
    suspicious: int = Field(default=0, description="Suspicious verdicts count")
    malicious: int = Field(default=0, description="Malicious verdicts count")
    quarantine: int = Field(default=0, description="Quarantine verdicts count")
    block: int = Field(default=0, description="Block verdicts count")


class AttackTypeTrendPoint(BaseModel):
    """Frequency and share of specific attack methodologies observed."""

    model_config = ConfigDict(from_attributes=True)

    attack_type: str = Field(description="Attack methodology identifier")
    count: int = Field(default=0, description="Number of threat signals matching this attack type")
    percentage: float = Field(default=0.0, description="Percentage share of total attack signals")


class RiskDistributionPoint(BaseModel):
    """Distribution of emails categorized across risk severity tiers."""

    model_config = ConfigDict(from_attributes=True)

    tier: str = Field(description="Risk classification tier: safe, low, medium, high, critical")
    count: int = Field(default=0, description="Count of analyses in this risk tier")
    percentage: float = Field(default=0.0, description="Percentage of total analyses")


class SenderDomainPoint(BaseModel):
    """Top sender domain telemetry and threat incidence rates."""

    model_config = ConfigDict(from_attributes=True)

    domain: str = Field(description="Sender domain name")
    total_emails: int = Field(default=0, description="Total emails received from domain")
    threat_count: int = Field(
        default=0, description="Threat emails (malicious/suspicious/quarantine/block)"
    )
    threat_rate: float = Field(
        default=0.0, description="Percentage of emails identified as threats"
    )
    clean_count: int = Field(default=0, description="Clean emails received from domain")


class DetectionRatePoint(BaseModel):
    """Historical timeline tracking overall threat detection rate percentage."""

    model_config = ConfigDict(from_attributes=True)

    timestamp: datetime = Field(description="Bucket start timestamp")
    total_analyzed: int = Field(default=0, description="Total emails processed in bucket")
    threats_detected: int = Field(default=0, description="Total threat emails in bucket")
    detection_rate: float = Field(
        default=0.0, description="Detection percentage (threats / total * 100)"
    )


class FalsePositiveStats(BaseModel):
    """User feedback metrics measuring false positive and detection accuracy."""

    model_config = ConfigDict(from_attributes=True)

    reported_count: int = Field(default=0, description="Total feedback reports submitted by users")
    confirmed_false_positive: int = Field(
        default=0, description="Confirmed false positive incidents"
    )
    false_positive_rate: float = Field(
        default=0.0, description="False positive rate percentage relative to threats detected"
    )


class MLPerformanceMetrics(BaseModel):
    """Inference performance, classification distribution, and latency for ML classifiers."""

    model_config = ConfigDict(from_attributes=True)

    total_predictions: int = Field(
        default=0, description="Total ML classification inferences performed"
    )
    avg_confidence: float = Field(
        default=0.0, description="Average confidence score across predictions"
    )
    avg_latency_ms: float = Field(
        default=0.0, description="Average ML inference latency in milliseconds"
    )
    phishing_detected: int = Field(default=0, description="Predictions classified as phishing")
    clean_detected: int = Field(default=0, description="Predictions classified as clean")
    spam_detected: int = Field(default=0, description="Predictions classified as spam")
    malware_detected: int = Field(default=0, description="Predictions classified as malware")


class LLMUtilizationMetrics(BaseModel):
    """Operational telemetry, token consumption, and safety compliance for LLM engines."""

    model_config = ConfigDict(from_attributes=True)

    total_calls: int = Field(default=0, description="Total LLM analysis invocations")
    avg_confidence: float = Field(default=0.0, description="Average self-reported confidence score")
    avg_latency_ms: float = Field(
        default=0.0, description="Average API roundtrip latency in milliseconds"
    )
    total_prompt_tokens: int = Field(default=0, description="Total prompt tokens consumed")
    total_completion_tokens: int = Field(default=0, description="Total completion tokens generated")
    total_tokens: int = Field(default=0, description="Combined total token usage")
    safety_pass_rate: float = Field(
        default=100.0, description="Percentage of responses passing safety gateway"
    )
    models_breakdown: dict[str, int] = Field(
        default_factory=dict, description="Invocations count per model name"
    )


class ProcessingLatencyStats(BaseModel):
    """End-to-end pipeline execution duration percentiles and extrema."""

    model_config = ConfigDict(from_attributes=True)

    p50_ms: float = Field(default=0.0, description="Median (50th percentile) latency in ms")
    p90_ms: float = Field(default=0.0, description="90th percentile latency in ms")
    p95_ms: float = Field(default=0.0, description="95th percentile latency in ms")
    p99_ms: float = Field(default=0.0, description="99th percentile latency in ms")
    avg_ms: float = Field(default=0.0, description="Mean pipeline execution duration in ms")
    min_ms: float = Field(default=0.0, description="Minimum observed latency in ms")
    max_ms: float = Field(default=0.0, description="Maximum observed latency in ms")


class ThreatIntelUsageStats(BaseModel):
    """Aggregated queries and hit rate distribution across external threat intelligence providers."""

    model_config = ConfigDict(from_attributes=True)

    total_queries: int = Field(default=0, description="Total external TI provider queries")
    malicious_hits: int = Field(default=0, description="Queries resulting in malicious verdict")
    suspicious_hits: int = Field(default=0, description="Queries resulting in suspicious verdict")
    clean_hits: int = Field(default=0, description="Queries resulting in clean verdict")
    unknown_hits: int = Field(default=0, description="Queries resulting in unknown verdict")
    providers_breakdown: dict[str, int] = Field(
        default_factory=dict, description="Query count breakdown per provider"
    )


class AnalyticsOverviewResponse(BaseModel):
    """Comprehensive analytics dashboard overview response."""

    model_config = ConfigDict(from_attributes=True)

    date_range: DateRangeMeta
    threat_trends: list[ThreatTrendPoint] = Field(default_factory=list)
    attack_type_trends: list[AttackTypeTrendPoint] = Field(default_factory=list)
    risk_distribution: list[RiskDistributionPoint] = Field(default_factory=list)
    sender_domains: list[SenderDomainPoint] = Field(default_factory=list)
    detection_rate: list[DetectionRatePoint] = Field(default_factory=list)
    false_positive_stats: FalsePositiveStats = Field(default_factory=FalsePositiveStats)
    ml_performance: MLPerformanceMetrics = Field(default_factory=MLPerformanceMetrics)
    llm_utilization: LLMUtilizationMetrics = Field(default_factory=LLMUtilizationMetrics)
    processing_latency: ProcessingLatencyStats = Field(default_factory=ProcessingLatencyStats)
    threat_intel_usage: ThreatIntelUsageStats = Field(default_factory=ThreatIntelUsageStats)
