"""Data contracts and schemas for the Threat Intelligence service.

Defines:
- IndicatorType: Standardized IOC category (domain, url, ip, hash).
- ThreatIntelReport: Normalized finding contract returned by all provider adapters.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import (
    AttackType,
    ReputationVerdict,
    ThreatCategory,
    ThreatSeverity,
)
from app.services.risk.schemas import ThreatIntelSignal


class IndicatorType(StrEnum):
    """Categorical classification of queried Indicators of Compromise (IOCs)."""

    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    HASH = "hash"


class ThreatIntelReport(BaseModel):
    """Authoritative normalized finding returned by any threat intelligence provider.

    Fields strictly fulfill the user requirements:
    - indicator
    - indicator_type
    - provider
    - reputation
    - confidence
    - source
    - timestamp
    - raw_reference
    """

    model_config = ConfigDict(frozen=True)

    indicator: str = Field(description="The evaluated IOC value (domain, URL, IP, or hash)")
    indicator_type: IndicatorType = Field(description="Taxonomy category of the indicator")
    provider: str = Field(
        description="Identifier of the provider adapter (e.g. 'virustotal', 'abuseipdb')"
    )
    reputation: ReputationVerdict = Field(
        default=ReputationVerdict.UNKNOWN,
        description="Assessed reputation status: 'clean', 'suspicious', 'malicious', or 'unknown'",
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Provider assessment confidence score (0.0 to 1.0)",
    )
    source: str = Field(
        description="Originating source description or API query endpoint",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the intelligence check was executed or cached",
    )
    raw_reference: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw provider metadata, response metrics, query tokens, or vendor tags",
    )

    # Operational & telemetry enrichments
    threat_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Normalized threat reputation score from 0.0 (benign) to 100.0 (malicious)",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Associated malware families, campaigns, or threat categorization tags",
    )
    error_message: str | None = Field(
        default=None,
        description="Sanitized failure reason if the provider encountered an issue",
    )
    is_cached: bool = Field(
        default=False,
        description="True if this result was resolved from the local TTL cache",
    )
    latency_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Query latency in milliseconds",
    )

    # -------------------------------------------------------------------------
    # Integration Converters
    # -------------------------------------------------------------------------

    def to_threat_intel_signal(self) -> ThreatIntelSignal:
        """Convert to Risk Engine input ThreatIntelSignal."""
        return ThreatIntelSignal(
            indicator_type=self.indicator_type.value,
            indicator_value=self.indicator,
            provider=self.provider,
            verdict=self.reputation,
            threat_score=self.threat_score,
            confidence=self.confidence,
            tags=self.tags,
            details=self.raw_reference,
        )

    def to_threat_signal(self) -> NormalizedThreatSignal:
        """Convert into canonical NormalizedThreatSignal for downstream pipeline consumption."""
        if self.reputation == ReputationVerdict.MALICIOUS:
            sev = ThreatSeverity.CRITICAL if self.threat_score >= 85.0 else ThreatSeverity.HIGH
            score = max(self.threat_score, 80.0)
        elif self.reputation == ReputationVerdict.SUSPICIOUS:
            sev = ThreatSeverity.MEDIUM
            score = max(self.threat_score, 50.0)
        elif self.reputation == ReputationVerdict.CLEAN:
            sev = ThreatSeverity.INFO
            score = 0.0
        else:
            sev = ThreatSeverity.INFO
            score = 0.0

        title = (
            f"Threat Intel finding for {self.indicator_type.value}: {self.reputation.value.upper()}"
        )
        desc = (
            f"Provider '{self.provider}' reported {self.reputation.value.upper()} reputation "
            f"with score {self.threat_score:.1f}/100 for {self.indicator_type.value} '{self.indicator}'. "
            f"Tags: {', '.join(self.tags) if self.tags else 'None'}."
        )

        return NormalizedThreatSignal(
            source="threat_intel",
            signal_type=f"TI_{self.indicator_type.value.upper()}_{self.reputation.value.upper()}",
            category=ThreatCategory.MALWARE if "malware" in self.tags else ThreatCategory.PHISHING,
            severity=sev,
            attack_type=AttackType.MALICIOUS_DOCUMENT
            if self.indicator_type == IndicatorType.HASH
            else AttackType.SPEAR_PHISHING,
            score=score,
            confidence=self.confidence,
            title=title,
            description=desc,
            evidence={
                "provider": self.provider,
                "reputation": self.reputation.value,
                "threat_score": self.threat_score,
                "tags": self.tags,
                "source": self.source,
            },
            indicator_value=self.indicator,
        )
