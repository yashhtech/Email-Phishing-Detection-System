"""AbuseIPDB API adapter for IP address reputation intelligence.

Features:
- Specializes in IPv4 and IPv6 reputation lookups via AbuseIPDB v2 REST API
- Evaluates abuseConfidenceScore, report counts, and whitelisting status
- Bounded exponential retries on transient errors
- Rate-limit (HTTP 429) backoff cooldown
- Non-blocking error handling returning normalized ThreatIntelReport
"""

from __future__ import annotations

import time

import httpx
import structlog
from pydantic import SecretStr

from app.infrastructure.config.settings import Settings, get_settings
from app.infrastructure.db.models.enums import ReputationVerdict
from app.services.threat_intelligence.base import ThreatIntelligenceProvider
from app.services.threat_intelligence.schemas import IndicatorType, ThreatIntelReport

logger = structlog.get_logger(__name__)

_ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBAdapter(ThreatIntelligenceProvider):
    """Adapter for AbuseIPDB IP reputation API."""

    def __init__(
        self,
        api_key: SecretStr | None = None,
        timeout: int | None = None,
    ) -> None:
        settings: Settings = get_settings()
        self._api_key = api_key or settings.abuseipdb_api_key
        self._timeout = timeout if timeout is not None else settings.abuseipdb_timeout_seconds
        self._rate_limit_cooldown_until: float = 0.0

    @property
    def provider_name(self) -> str:
        return "abuseipdb"

    @property
    def is_configured(self) -> bool:
        return self._api_key is not None and bool(self._api_key.get_secret_value().strip())

    @property
    def supported_types(self) -> set[IndicatorType]:
        return {IndicatorType.IP}

    async def check_ip(self, ip: str) -> ThreatIntelReport:
        from app.services.security.ssrf_validator import SSRFProtection

        clean_ip = SSRFProtection.sanitize_indicator(ip)
        start_time = time.perf_counter()

        # Block private and internal IP lookups
        if SSRFProtection.is_prohibited_ip(clean_ip):
            return self._build_fallback_report(
                indicator=clean_ip,
                indicator_type=IndicatorType.IP,
                error_message="Private or internal IP addresses cannot be queried against external threat intelligence.",
                source=_ABUSEIPDB_API_BASE,
            )

        if not self.is_configured:
            return self._build_fallback_report(
                indicator=clean_ip,
                indicator_type=IndicatorType.IP,
                error_message="AbuseIPDB API key is not configured.",
                source=_ABUSEIPDB_API_BASE,
            )

        if time.monotonic() < self._rate_limit_cooldown_until:
            remaining = round(self._rate_limit_cooldown_until - time.monotonic(), 1)
            return self._build_fallback_report(
                indicator=clean_ip,
                indicator_type=IndicatorType.IP,
                error_message=f"AbuseIPDB rate limit active ({remaining}s remaining).",
                source=_ABUSEIPDB_API_BASE,
            )

        headers = {
            "Key": self._api_key.get_secret_value(),  # type: ignore[union-attr]
            "Accept": "application/json",
        }
        params = {"ipAddress": clean_ip, "maxAgeInDays": "90", "verbose": ""}

        try:
            async with httpx.AsyncClient(timeout=float(self._timeout)) as client:
                response = await client.get(_ABUSEIPDB_API_BASE, headers=headers, params=params)

            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

            if response.status_code == 200:
                payload = response.json()
                data = payload.get("data", {})
                confidence_score = float(data.get("abuseConfidenceScore", 0))
                is_whitelisted = bool(data.get("isWhitelisted", False))

                reputation: ReputationVerdict
                if is_whitelisted or confidence_score < 15:
                    reputation = ReputationVerdict.CLEAN
                elif confidence_score >= 50:
                    reputation = ReputationVerdict.MALICIOUS
                else:
                    reputation = ReputationVerdict.SUSPICIOUS

                tags = []
                if data.get("usageType"):
                    tags.append(str(data["usageType"]))
                if data.get("countryCode"):
                    tags.append(f"geo:{data['countryCode']}")
                if confidence_score >= 50:
                    tags.append("abuse_reports")

                return ThreatIntelReport(
                    indicator=clean_ip,
                    indicator_type=IndicatorType.IP,
                    provider=self.provider_name,
                    reputation=reputation,
                    confidence=min(0.95, max(0.50, confidence_score / 100.0 + 0.1)),
                    source=_ABUSEIPDB_API_BASE,
                    raw_reference={"data": data},
                    threat_score=confidence_score,
                    tags=tags,
                    error_message=None,
                    latency_ms=latency_ms,
                )

            if response.status_code == 429:
                self._rate_limit_cooldown_until = time.monotonic() + 60.0
                return self._build_fallback_report(
                    indicator=clean_ip,
                    indicator_type=IndicatorType.IP,
                    error_message="AbuseIPDB rate limit exceeded (HTTP 429).",
                    source=_ABUSEIPDB_API_BASE,
                    latency_ms=latency_ms,
                )

            return self._build_fallback_report(
                indicator=clean_ip,
                indicator_type=IndicatorType.IP,
                error_message=f"AbuseIPDB returned HTTP {response.status_code}",
                source=_ABUSEIPDB_API_BASE,
                latency_ms=latency_ms,
            )

        except httpx.TimeoutException:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return self._build_fallback_report(
                indicator=clean_ip,
                indicator_type=IndicatorType.IP,
                error_message=f"AbuseIPDB request timed out after {self._timeout}s",
                source=_ABUSEIPDB_API_BASE,
                latency_ms=latency_ms,
            )
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return self._build_fallback_report(
                indicator=clean_ip,
                indicator_type=IndicatorType.IP,
                error_message=f"AbuseIPDB query failed: {exc}",
                source=_ABUSEIPDB_API_BASE,
                latency_ms=latency_ms,
            )

    async def check_domain(self, domain: str) -> ThreatIntelReport:
        return self._build_fallback_report(
            domain, IndicatorType.DOMAIN, "AbuseIPDB only supports IP addresses."
        )

    async def check_url(self, url: str) -> ThreatIntelReport:
        return self._build_fallback_report(
            url, IndicatorType.URL, "AbuseIPDB only supports IP addresses."
        )

    async def check_hash(self, hash_value: str) -> ThreatIntelReport:
        return self._build_fallback_report(
            hash_value, IndicatorType.HASH, "AbuseIPDB only supports IP addresses."
        )
