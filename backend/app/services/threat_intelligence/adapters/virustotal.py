"""VirusTotal v3 API adapter for threat intelligence queries.

Features:
- Queries domains, URLs, IPv4/IPv6, and file hashes (SHA256, MD5) via VT v3 REST API
- URL ID canonicalization using unpadded Base64 encoding according to RFC 4648
- Exponential backoff with jitter on 5xx server errors
- HTTP 429 rate-limit handling with temporary cooldown backoff
- Strict configurable timeout via VIRUSTOTAL_TIMEOUT_SECONDS
- Safe fallback reporting: Never raises unhandled exceptions or crashes caller
- Never logs API keys or authorization headers
"""

from __future__ import annotations

import asyncio
import base64
import random
import time
from typing import Any

import httpx
import structlog
from pydantic import SecretStr

from app.infrastructure.config.settings import Settings, get_settings
from app.infrastructure.db.models.enums import ReputationVerdict
from app.services.threat_intelligence.base import ThreatIntelligenceProvider
from app.services.threat_intelligence.schemas import IndicatorType, ThreatIntelReport

logger = structlog.get_logger(__name__)

_VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalAdapter(ThreatIntelligenceProvider):
    """Adapter for VirusTotal v3 REST API."""

    def __init__(
        self,
        api_key: SecretStr | None = None,
        timeout: int | None = None,
        max_retries: int | None = None,
    ) -> None:
        settings: Settings = get_settings()
        self._api_key = api_key or settings.virustotal_api_key
        self._timeout = timeout if timeout is not None else settings.virustotal_timeout_seconds
        self._max_retries = (
            max_retries if max_retries is not None else settings.virustotal_max_retries
        )
        self._rate_limit_cooldown_until: float = 0.0

    @property
    def provider_name(self) -> str:
        return "virustotal"

    @property
    def is_configured(self) -> bool:
        return self._api_key is not None and bool(self._api_key.get_secret_value().strip())

    @property
    def is_rate_limited(self) -> bool:
        """True if the adapter is currently within a temporary rate-limit cooldown window."""
        return time.monotonic() < self._rate_limit_cooldown_until

    # -------------------------------------------------------------------------
    # Public Abstract Method Implementations
    # -------------------------------------------------------------------------

    async def check_domain(self, domain: str) -> ThreatIntelReport:
        from app.services.security.ssrf_validator import SSRFProtection

        clean_domain = SSRFProtection.sanitize_indicator(domain).lower()
        endpoint = f"{_VT_API_BASE}/domains/{clean_domain}"
        return await self._execute_query(
            endpoint=endpoint,
            indicator=clean_domain,
            indicator_type=IndicatorType.DOMAIN,
        )

    async def check_url(self, url: str) -> ThreatIntelReport:
        from app.services.security.ssrf_validator import SSRFProtection

        clean_url = SSRFProtection.sanitize_indicator(url)
        # Check against private network targets (SSRF defense)
        is_safe, reason = SSRFProtection.validate_url(clean_url)
        if not is_safe:
            return self._build_fallback_report(
                indicator=clean_url,
                indicator_type=IndicatorType.URL,
                error_message=f"SSRF validation blocked: {reason}",
            )

        # VT v3 URL identifier is unpadded base64 of the URL
        url_id = base64.urlsafe_b64encode(clean_url.encode()).decode().rstrip("=")
        endpoint = f"{_VT_API_BASE}/urls/{url_id}"
        return await self._execute_query(
            endpoint=endpoint,
            indicator=clean_url,
            indicator_type=IndicatorType.URL,
        )

    async def check_ip(self, ip: str) -> ThreatIntelReport:
        from app.services.security.ssrf_validator import SSRFProtection

        clean_ip = SSRFProtection.sanitize_indicator(ip)
        # Never send internal/private RFC 1918 or loopback IPs to external providers
        if SSRFProtection.is_prohibited_ip(clean_ip):
            return self._build_fallback_report(
                indicator=clean_ip,
                indicator_type=IndicatorType.IP,
                error_message="Private or internal IP addresses cannot be queried against external threat intelligence.",
            )

        endpoint = f"{_VT_API_BASE}/ip_addresses/{clean_ip}"
        return await self._execute_query(
            endpoint=endpoint,
            indicator=clean_ip,
            indicator_type=IndicatorType.IP,
        )

    async def check_hash(self, hash_value: str) -> ThreatIntelReport:
        from app.services.security.ssrf_validator import SSRFProtection

        clean_hash = SSRFProtection.sanitize_indicator(hash_value).lower()
        endpoint = f"{_VT_API_BASE}/files/{clean_hash}"
        return await self._execute_query(
            endpoint=endpoint,
            indicator=clean_hash,
            indicator_type=IndicatorType.HASH,
        )


    # -------------------------------------------------------------------------
    # Resilient Query Execution
    # -------------------------------------------------------------------------

    async def _execute_query(
        self,
        endpoint: str,
        indicator: str,
        indicator_type: IndicatorType,
    ) -> ThreatIntelReport:
        start_time = time.perf_counter()

        # 1. Check if configured
        if not self.is_configured:
            return self._build_fallback_report(
                indicator=indicator,
                indicator_type=indicator_type,
                error_message="VirusTotal API key is not configured.",
                source=endpoint,
            )

        # 2. Check if in rate-limit cooldown
        if self.is_rate_limited:
            remaining = round(self._rate_limit_cooldown_until - time.monotonic(), 1)
            logger.warning(
                "virustotal_rate_limit_cooldown_active",
                indicator=indicator,
                remaining_seconds=remaining,
            )
            return self._build_fallback_report(
                indicator=indicator,
                indicator_type=indicator_type,
                error_message=f"VirusTotal rate limit active (cooldown {remaining}s remaining).",
                source=endpoint,
            )

        headers = {
            "x-apikey": self._api_key.get_secret_value(),  # type: ignore[union-attr]
            "Accept": "application/json",
        }

        # 3. Retry loop with exponential backoff
        for attempt in range(self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=float(self._timeout)) as client:
                    response = await client.get(endpoint, headers=headers)

                latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

                # 200 OK
                if response.status_code == 200:
                    payload = response.json()
                    return self._parse_vt_response(
                        payload=payload,
                        indicator=indicator,
                        indicator_type=indicator_type,
                        endpoint=endpoint,
                        latency_ms=latency_ms,
                    )

                # 404 Not Found (indicator unknown to VirusTotal)
                if response.status_code == 404:
                    return ThreatIntelReport(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider=self.provider_name,
                        reputation=ReputationVerdict.UNKNOWN,
                        confidence=0.5,
                        source=endpoint,
                        raw_reference={
                            "status": 404,
                            "message": "Indicator not found in VirusTotal database.",
                        },
                        threat_score=0.0,
                        tags=[],
                        error_message=None,
                        latency_ms=latency_ms,
                    )

                # 429 Rate Limit
                if response.status_code == 429:
                    # Enforce a 60-second cooldown window
                    self._rate_limit_cooldown_until = time.monotonic() + 60.0
                    logger.warning("virustotal_rate_limit_exceeded", indicator=indicator)
                    return self._build_fallback_report(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        error_message="VirusTotal rate limit exceeded (HTTP 429).",
                        source=endpoint,
                        latency_ms=latency_ms,
                        raw_reference={"status": 429},
                    )

                # 5xx Server Errors (retryable)
                if response.status_code in (500, 502, 503, 504) and attempt < self._max_retries:
                    delay = (2**attempt) + random.uniform(0.1, 0.4)
                    logger.warning(
                        "virustotal_server_error_retrying",
                        status_code=response.status_code,
                        attempt=attempt + 1,
                        delay=delay,
                    )
                    await asyncio.sleep(delay)
                    continue

                # Permanent error
                return self._build_fallback_report(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    error_message=f"VirusTotal API returned HTTP {response.status_code}",
                    source=endpoint,
                    latency_ms=latency_ms,
                    raw_reference={"status": response.status_code},
                )

            except httpx.TimeoutException:
                if attempt < self._max_retries:
                    await asyncio.sleep(1.0)
                    continue
                latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                logger.warning(
                    "virustotal_query_timeout", indicator=indicator, latency_ms=latency_ms
                )
                return self._build_fallback_report(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    error_message=f"VirusTotal request timed out after {self._timeout}s",
                    source=endpoint,
                    latency_ms=latency_ms,
                )

            except Exception as exc:
                latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                logger.error("virustotal_unexpected_error", error=str(exc), indicator=indicator)
                return self._build_fallback_report(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    error_message=f"VirusTotal request failed: {exc}",
                    source=endpoint,
                    latency_ms=latency_ms,
                )

        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        return self._build_fallback_report(
            indicator=indicator,
            indicator_type=indicator_type,
            error_message="VirusTotal retries exhausted.",
            source=endpoint,
            latency_ms=latency_ms,
        )

    # -------------------------------------------------------------------------
    # Response Parsing & Normalization
    # -------------------------------------------------------------------------

    def _parse_vt_response(
        self,
        payload: dict[str, Any],
        indicator: str,
        indicator_type: IndicatorType,
        endpoint: str,
        latency_ms: float,
    ) -> ThreatIntelReport:
        """Parse VirusTotal v3 payload into normalized ThreatIntelReport."""
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected

        tags = attributes.get("tags", [])
        categories = attributes.get("categories", {})
        if categories and isinstance(categories, dict):
            tags.extend(list(categories.values())[:3])

        # Reputation assessment logic
        reputation: ReputationVerdict
        threat_score: float
        confidence: float

        if malicious >= 3:
            reputation = ReputationVerdict.MALICIOUS
            threat_score = min(100.0, 75.0 + (malicious * 2.5))
            confidence = min(0.99, 0.80 + (malicious / max(total_engines, 1)) * 0.20)
        elif malicious >= 1 or suspicious >= 2:
            reputation = ReputationVerdict.SUSPICIOUS
            threat_score = min(74.0, 50.0 + (malicious * 10.0) + (suspicious * 5.0))
            confidence = 0.75
        elif harmless >= 5 and malicious == 0:
            reputation = ReputationVerdict.CLEAN
            threat_score = 0.0
            confidence = 0.90
        else:
            reputation = ReputationVerdict.UNKNOWN
            threat_score = 10.0 if suspicious > 0 else 0.0
            confidence = 0.50

        raw_reference = {
            "id": payload.get("data", {}).get("id"),
            "stats": stats,
            "reputation_score": attributes.get("reputation", 0),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }

        return ThreatIntelReport(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=self.provider_name,
            reputation=reputation,
            confidence=round(confidence, 2),
            source=endpoint,
            raw_reference=raw_reference,
            threat_score=round(threat_score, 1),
            tags=tags[:10],
            error_message=None,
            is_cached=False,
            latency_ms=latency_ms,
        )
