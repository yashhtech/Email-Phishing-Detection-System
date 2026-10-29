"""Threat Intelligence Manager & Multi-Provider Coordinator.

Responsibilities:
1. Orchestrate multiple pluggable ThreatIntelligenceProvider adapters.
2. Coordinate thread-safe caching to avoid duplicate queries and respect provider rate limits.
3. Query multiple providers concurrently with graceful degradation and non-blocking failure recovery.
4. Synthesize multi-vendor consensus into authoritative ThreatIntelReport findings.
5. Ingest EmailAnalysisInput, automatically extract all forensic indicators, and query TI in one resilient pass.
"""

from __future__ import annotations

import asyncio
import re

import structlog

from app.domain.entities.email_analysis_input import EmailAnalysisInput
from app.infrastructure.config.settings import Settings, get_settings
from app.infrastructure.db.models.enums import ReputationVerdict
from app.services.threat_intelligence.adapters.abuseipdb import AbuseIPDBAdapter
from app.services.threat_intelligence.adapters.internal import InternalThreatIntelAdapter
from app.services.threat_intelligence.adapters.virustotal import VirusTotalAdapter
from app.services.threat_intelligence.base import ThreatIntelligenceProvider
from app.services.threat_intelligence.cache import ThreatIntelCache
from app.services.threat_intelligence.schemas import IndicatorType, ThreatIntelReport

logger = structlog.get_logger(__name__)

# Basic IP regex for auto-detecting indicator types if not explicitly specified
_IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


class ThreatIntelligenceService:
    """Enterprise coordinator for multi-provider threat intelligence operations."""

    def __init__(
        self,
        providers: list[ThreatIntelligenceProvider] | None = None,
        cache: ThreatIntelCache | None = None,
    ) -> None:
        settings: Settings = get_settings()
        self._cache = cache or ThreatIntelCache(
            default_ttl_seconds=settings.threat_intel_cache_ttl_seconds
        )
        self._providers: dict[str, ThreatIntelligenceProvider] = {}

        if providers is not None:
            for p in providers:
                self.register_provider(p)
        else:
            # Default production initialization
            self.register_provider(InternalThreatIntelAdapter())
            self.register_provider(VirusTotalAdapter())
            self.register_provider(AbuseIPDBAdapter())

    # -------------------------------------------------------------------------
    # Provider Registry
    # -------------------------------------------------------------------------

    def register_provider(self, provider: ThreatIntelligenceProvider) -> None:
        """Register a new threat intelligence provider adapter."""
        self._providers[provider.provider_name.lower()] = provider
        logger.info(
            "threat_intel_provider_registered",
            provider=provider.provider_name,
            is_configured=provider.is_configured,
        )

    def get_provider(self, name: str) -> ThreatIntelligenceProvider | None:
        """Retrieve registered provider by name."""
        return self._providers.get(name.lower())

    def list_providers(self) -> list[str]:
        """List names of all registered providers."""
        return list(self._providers.keys())

    @property
    def configured_providers(self) -> list[str]:
        """List names of active, configured providers."""
        return [name for name, p in self._providers.items() if p.is_configured]

    # -------------------------------------------------------------------------
    # Public Single Indicator Checks
    # -------------------------------------------------------------------------

    async def check_domain(self, domain: str) -> ThreatIntelReport:
        """Check threat intelligence for a domain."""
        return await self.check_indicator(domain, IndicatorType.DOMAIN)

    async def check_url(self, url: str) -> ThreatIntelReport:
        """Check threat intelligence for a full URL."""
        return await self.check_indicator(url, IndicatorType.URL)

    async def check_ip(self, ip: str) -> ThreatIntelReport:
        """Check threat intelligence for an IP address."""
        return await self.check_indicator(ip, IndicatorType.IP)

    async def check_hash(self, hash_value: str) -> ThreatIntelReport:
        """Check threat intelligence for a file hash."""
        return await self.check_indicator(hash_value, IndicatorType.HASH)

    async def check_indicator(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        preferred_provider: str | None = None,
    ) -> ThreatIntelReport:
        """Query reputation for an indicator across active providers.

        Checks local TTL cache first. If un-cached, executes concurrent queries
        across supported configured providers and aggregates findings into an
        authoritative report.
        """
        clean_indicator = indicator.strip()
        if not clean_indicator:
            return self._build_empty_report(indicator, indicator_type)

        # 1. Check local TTL cache
        cache_lookup_provider = preferred_provider or "aggregated"
        cached = self._cache.get(cache_lookup_provider, indicator_type, clean_indicator)
        if cached is not None:
            return cached

        # 2. Select eligible providers
        eligible_providers: list[ThreatIntelligenceProvider] = []
        if preferred_provider:
            p = self.get_provider(preferred_provider)
            if p and p.is_configured and indicator_type in p.supported_types:
                eligible_providers.append(p)

        if not eligible_providers:
            eligible_providers = [
                p
                for p in self._providers.values()
                if p.is_configured and indicator_type in p.supported_types
            ]

        if not eligible_providers:
            # No configured provider for this type
            report = ThreatIntelReport(
                indicator=clean_indicator,
                indicator_type=indicator_type,
                provider="none",
                reputation=ReputationVerdict.UNKNOWN,
                confidence=0.0,
                source="threat_intel://unconfigured",
                error_message="No configured threat intelligence provider available for this indicator type.",
            )
            return report

        # 3. Concurrently query all eligible providers
        tasks = [
            provider.check_indicator(clean_indicator, indicator_type)
            for provider in eligible_providers
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_reports: list[ThreatIntelReport] = []
        for res in results:
            if isinstance(res, ThreatIntelReport):
                valid_reports.append(res)
            elif isinstance(res, Exception):
                logger.warning(
                    "threat_intel_provider_exception", error=str(res), indicator=clean_indicator
                )

        if not valid_reports:
            return ThreatIntelReport(
                indicator=clean_indicator,
                indicator_type=indicator_type,
                provider="aggregated",
                reputation=ReputationVerdict.UNKNOWN,
                confidence=0.0,
                source="threat_intel://all_failed",
                error_message="All threat intelligence providers failed to return results.",
            )

        # 4. Aggregate findings across providers
        aggregated = self._aggregate_reports(clean_indicator, indicator_type, valid_reports)

        # 5. Store in cache
        self._cache.set(cache_lookup_provider, indicator_type, clean_indicator, aggregated)

        return aggregated

    # -------------------------------------------------------------------------
    # Batch & Pipeline Integration
    # -------------------------------------------------------------------------

    async def check_indicators_batch(
        self,
        indicators: list[tuple[str, IndicatorType]],
        max_concurrency: int = 5,
    ) -> list[ThreatIntelReport]:
        """Execute concurrent indicator checks with bounded concurrency throttling."""
        semaphore = asyncio.Semaphore(max_concurrency)

        async def _check_with_semaphore(ind: str, ind_type: IndicatorType) -> ThreatIntelReport:
            async with semaphore:
                return await self.check_indicator(ind, ind_type)

        tasks = [_check_with_semaphore(ind, ind_type) for ind, ind_type in indicators]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        reports: list[ThreatIntelReport] = []
        for i, res in enumerate(results):
            if isinstance(res, ThreatIntelReport):
                reports.append(res)
            else:
                ind, ind_type = indicators[i]
                reports.append(
                    ThreatIntelReport(
                        indicator=ind,
                        indicator_type=ind_type,
                        provider="aggregated",
                        reputation=ReputationVerdict.UNKNOWN,
                        confidence=0.0,
                        source="threat_intel://batch_error",
                        error_message=f"Batch execution error: {res}",
                    )
                )

        return reports

    async def extract_and_check_email(
        self,
        email_input: EmailAnalysisInput,
        max_indicators: int = 15,
    ) -> list[ThreatIntelReport]:
        """Extract all forensic indicators from an email and check them in a non-blocking pass.

        Extracts:
        - Sender domain
        - Extracted domains
        - Unique URLs
        - Originating IP
        - Attachment SHA256 and MD5 hashes
        """
        indicators_to_check: list[tuple[str, IndicatorType]] = []
        seen: set[str] = set()

        def _add(val: str | None, ind_type: IndicatorType) -> None:
            if val and val.strip() and val.strip().lower() not in seen:
                indicators_to_check.append((val.strip(), ind_type))
                seen.add(val.strip().lower())

        # 1. Sender domain & extracted domains
        if email_input.sender.domain:
            _add(email_input.sender.domain, IndicatorType.DOMAIN)
        for d in email_input.domains[:5]:
            _add(d, IndicatorType.DOMAIN)

        # 2. URLs (top suspicious or unique)
        for u in email_input.urls[:5]:
            _add(u.canonical_url or u.raw_url, IndicatorType.URL)

        # 3. Originating IP
        if email_input.headers.x_originating_ip:
            _add(email_input.headers.x_originating_ip, IndicatorType.IP)

        # 4. Attachment hashes
        for att in email_input.attachments[:4]:
            if att.sha256_hash:
                _add(att.sha256_hash, IndicatorType.HASH)
            elif att.md5_hash:
                _add(att.md5_hash, IndicatorType.HASH)

        # Enforce safety cap to avoid overwhelming downstream services
        selected_indicators = indicators_to_check[:max_indicators]

        logger.info(
            "threat_intel_email_extraction_started",
            email_id=email_input.analysis_input_id,
            indicator_count=len(selected_indicators),
        )

        return await self.check_indicators_batch(selected_indicators)

    # -------------------------------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------------------------------

    def _aggregate_reports(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        reports: list[ThreatIntelReport],
    ) -> ThreatIntelReport:
        """Aggregate multiple provider reports into a single authoritative verdict.

        Rule:
        - If ANY reputable provider says MALICIOUS -> MALICIOUS
        - Else if ANY says SUSPICIOUS -> SUSPICIOUS
        - Else if ANY says CLEAN and none suspicious/malicious -> CLEAN
        - Else -> UNKNOWN
        """
        if len(reports) == 1:
            return reports[0]

        malicious_reports = [r for r in reports if r.reputation == ReputationVerdict.MALICIOUS]
        suspicious_reports = [r for r in reports if r.reputation == ReputationVerdict.SUSPICIOUS]
        clean_reports = [r for r in reports if r.reputation == ReputationVerdict.CLEAN]

        highest_score = max(r.threat_score for r in reports)
        aggregated_tags: set[str] = set()
        for r in reports:
            aggregated_tags.update(r.tags)

        reputation: ReputationVerdict
        winning_provider: str
        confidence: float
        source: str

        if malicious_reports:
            reputation = ReputationVerdict.MALICIOUS
            top = max(malicious_reports, key=lambda x: x.threat_score)
            winning_provider = (
                f"{top.provider} (multi-provider consensus: {len(malicious_reports)} flagged)"
            )
            confidence = max(r.confidence for r in malicious_reports)
            source = top.source
        elif suspicious_reports:
            reputation = ReputationVerdict.SUSPICIOUS
            top = max(suspicious_reports, key=lambda x: x.threat_score)
            winning_provider = (
                f"{top.provider} (multi-provider consensus: {len(suspicious_reports)} flagged)"
            )
            confidence = max(r.confidence for r in suspicious_reports)
            source = top.source
        elif clean_reports:
            reputation = ReputationVerdict.CLEAN
            top = clean_reports[0]
            winning_provider = f"{top.provider} (clean consensus)"
            confidence = max(r.confidence for r in clean_reports)
            source = top.source
        else:
            reputation = ReputationVerdict.UNKNOWN
            winning_provider = "aggregated"
            confidence = 0.5
            source = "threat_intel://consensus"

        raw_reference = {
            "individual_provider_reports": [
                {
                    "provider": r.provider,
                    "reputation": r.reputation.value,
                    "score": r.threat_score,
                    "tags": r.tags,
                }
                for r in reports
            ]
        }

        return ThreatIntelReport(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=winning_provider,
            reputation=reputation,
            confidence=confidence,
            source=source,
            raw_reference=raw_reference,
            threat_score=highest_score,
            tags=list(aggregated_tags)[:15],
            error_message=None,
        )

    def _build_empty_report(
        self, indicator: str, indicator_type: IndicatorType
    ) -> ThreatIntelReport:
        return ThreatIntelReport(
            indicator=indicator,
            indicator_type=indicator_type,
            provider="none",
            reputation=ReputationVerdict.UNKNOWN,
            confidence=0.0,
            source="threat_intel://empty",
            error_message="Empty indicator provided.",
        )


_global_ti_service: ThreatIntelligenceService | None = None


def get_threat_intel_service() -> ThreatIntelligenceService:
    """Return the application-wide ThreatIntelligenceService singleton.

    Sharing the singleton ensures that the in-memory ThreatIntelCache
    is preserved across multiple email analyses, preventing redundant
    external lookups for recurring indicators.
    """
    global _global_ti_service
    if _global_ti_service is None:
        _global_ti_service = ThreatIntelligenceService()
    return _global_ti_service

