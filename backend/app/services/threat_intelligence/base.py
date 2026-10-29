"""Provider abstraction and protocol for Threat Intelligence integrations.

Design Invariants:
1. Provider-Agnostic Abstraction: Business logic never depends directly on a concrete provider.
2. Graceful Failure Invariant: Provider checks never raise unhandled exceptions; they return
   normalized ThreatIntelReport with ReputationVerdict.UNKNOWN on failures or timeouts.
3. Multi-Indicator Support: All adapters adhere to domain, URL, IP, and hash query contracts.
4. Non-Blocking Execution: Asynchronous methods compatible with background workers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from app.infrastructure.db.models.enums import ReputationVerdict
from app.services.threat_intelligence.schemas import IndicatorType, ThreatIntelReport


class ThreatIntelligenceProvider(ABC):
    """Abstract Base Class defining the contract for all threat intelligence adapters."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique provider identifier (e.g. 'virustotal', 'abuseipdb', 'internal_blocklist')."""
        ...

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """True if the provider has valid credentials and is ready to execute queries."""
        ...

    @property
    def supported_types(self) -> set[IndicatorType]:
        """Set of IndicatorType values supported by this adapter. Default: all types."""
        return {
            IndicatorType.DOMAIN,
            IndicatorType.URL,
            IndicatorType.IP,
            IndicatorType.HASH,
        }

    @abstractmethod
    async def check_domain(self, domain: str) -> ThreatIntelReport:
        """Query reputation for a domain name."""
        ...

    @abstractmethod
    async def check_url(self, url: str) -> ThreatIntelReport:
        """Query reputation for a full URL."""
        ...

    @abstractmethod
    async def check_ip(self, ip: str) -> ThreatIntelReport:
        """Query reputation for an IPv4 or IPv6 address."""
        ...

    @abstractmethod
    async def check_hash(self, hash_value: str) -> ThreatIntelReport:
        """Query reputation for a file hash (SHA256, MD5, SHA1)."""
        ...

    async def check_indicator(
        self,
        indicator: str,
        indicator_type: IndicatorType,
    ) -> ThreatIntelReport:
        """Generic dispatcher routing an indicator to the appropriate check method."""
        if indicator_type not in self.supported_types:
            return self._build_fallback_report(
                indicator=indicator,
                indicator_type=indicator_type,
                error_message=f"Indicator type '{indicator_type.value}' is not supported by {self.provider_name}",
                source=f"{self.provider_name}://unsupported",
            )

        if indicator_type == IndicatorType.DOMAIN:
            return await self.check_domain(indicator)
        elif indicator_type == IndicatorType.URL:
            return await self.check_url(indicator)
        elif indicator_type == IndicatorType.IP:
            return await self.check_ip(indicator)
        elif indicator_type == IndicatorType.HASH:
            return await self.check_hash(indicator)
        else:
            return self._build_fallback_report(
                indicator=indicator,
                indicator_type=indicator_type,
                error_message=f"Unknown indicator type: {indicator_type}",
                source=f"{self.provider_name}://unknown",
            )

    def _build_fallback_report(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        error_message: str | None = None,
        source: str | None = None,
        latency_ms: float = 0.0,
        raw_reference: dict[str, Any] | None = None,
    ) -> ThreatIntelReport:
        """Construct safe fallback report when query fails, is unconfigured, or times out."""
        return ThreatIntelReport(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=self.provider_name,
            reputation=ReputationVerdict.UNKNOWN,
            confidence=0.0,
            source=source or f"{self.provider_name}://error",
            timestamp=datetime.now(UTC),
            raw_reference=raw_reference or {},
            threat_score=0.0,
            tags=[],
            error_message=error_message,
            is_cached=False,
            latency_ms=latency_ms,
        )
