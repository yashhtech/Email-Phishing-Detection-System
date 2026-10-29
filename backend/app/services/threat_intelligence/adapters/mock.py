"""Deterministic mock threat intelligence adapter for automated unit testing."""

from __future__ import annotations

from app.infrastructure.db.models.enums import ReputationVerdict
from app.services.threat_intelligence.base import ThreatIntelligenceProvider
from app.services.threat_intelligence.schemas import IndicatorType, ThreatIntelReport


class MockThreatIntelAdapter(ThreatIntelligenceProvider):
    """Controllable mock adapter supporting simulated timeouts, errors, and predefined responses."""

    def __init__(
        self,
        provider_name: str = "mock_provider",
        is_configured: bool = True,
        simulate_timeout: bool = False,
        simulate_failure: bool = False,
        simulate_rate_limit: bool = False,
    ) -> None:
        self._name = provider_name
        self._configured = is_configured
        self.simulate_timeout = simulate_timeout
        self.simulate_failure = simulate_failure
        self.simulate_rate_limit = simulate_rate_limit
        self._canned_responses: dict[str, ThreatIntelReport] = {}
        self.query_count = 0

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def is_configured(self) -> bool:
        return self._configured

    def set_canned_response(self, indicator: str, report: ThreatIntelReport) -> None:
        """Pre-seed an explicit report for an indicator."""
        self._canned_responses[indicator.strip().lower()] = report

    async def _handle_query(
        self, indicator: str, indicator_type: IndicatorType
    ) -> ThreatIntelReport:
        self.query_count += 1
        clean = indicator.strip().lower()

        if not self.is_configured:
            return self._build_fallback_report(
                indicator=indicator,
                indicator_type=indicator_type,
                error_message=f"{self.provider_name} is unconfigured.",
            )

        if self.simulate_timeout:
            return self._build_fallback_report(
                indicator=indicator,
                indicator_type=indicator_type,
                error_message=f"Simulated timeout on {self.provider_name}",
            )

        if self.simulate_rate_limit:
            return self._build_fallback_report(
                indicator=indicator,
                indicator_type=indicator_type,
                error_message=f"Simulated rate limit (429) on {self.provider_name}",
            )

        if self.simulate_failure:
            return self._build_fallback_report(
                indicator=indicator,
                indicator_type=indicator_type,
                error_message=f"Simulated internal failure on {self.provider_name}",
            )

        if clean in self._canned_responses:
            return self._canned_responses[clean]

        # Default clean/unknown response
        return ThreatIntelReport(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=self.provider_name,
            reputation=ReputationVerdict.UNKNOWN,
            confidence=0.5,
            source=f"{self.provider_name}://mock",
            raw_reference={"status": "mock_default"},
            threat_score=0.0,
            tags=[],
        )

    async def check_domain(self, domain: str) -> ThreatIntelReport:
        return await self._handle_query(domain, IndicatorType.DOMAIN)

    async def check_url(self, url: str) -> ThreatIntelReport:
        return await self._handle_query(url, IndicatorType.URL)

    async def check_ip(self, ip: str) -> ThreatIntelReport:
        return await self._handle_query(ip, IndicatorType.IP)

    async def check_hash(self, hash_value: str) -> ThreatIntelReport:
        return await self._handle_query(hash_value, IndicatorType.HASH)
