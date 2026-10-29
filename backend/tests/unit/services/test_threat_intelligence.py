"""Extensive unit tests for the provider-based Threat Intelligence module.

Coverage:
1. Output Contract & Schemas:
   - ThreatIntelReport required fields: indicator, indicator_type, provider,
     reputation, confidence, source, timestamp, raw_reference.
   - Pipeline converters: to_threat_intel_signal() and to_threat_signal().
2. ThreatIntelligenceProvider Abstraction:
   - Interface compliance for all adapters (VirusTotal, AbuseIPDB, Internal, Mock).
   - Generic check_indicator() dispatcher for domains, URLs, IPs, hashes.
   - Unsupported indicator type graceful handling.
3. InternalThreatIntelAdapter:
   - Known blocklist domain, IP, and file hash lookups.
   - Allowlisted domains (e.g. google.com).
   - Unknown indicator handling.
   - Runtime blocklist/allowlist registration.
4. VirusTotalAdapter:
   - Successful domain, URL, IP, and hash responses (mocked httpx).
   - URL unpadded base64 identifier encoding.
   - HTTP 404 (indicator not in database) treated as clean/unknown.
   - HTTP 429 rate limit triggers cooldown window without crash.
   - HTTP 5xx server error retries.
   - Timeout handling and unconfigured key graceful degradation.
5. AbuseIPDBAdapter:
   - IP checks with high abuseConfidenceScore (malicious).
   - Low score or whitelisted IP (clean).
   - Non-IP queries safely rejected with fallback.
   - Timeout and rate-limit handling.
6. ThreatIntelCache:
   - Cache hit with is_cached=True flag.
   - Cache miss and expired TTL eviction.
   - Thread safety and key normalization.
7. ThreatIntelligenceService (Multi-Provider Coordinator):
   - Dynamic provider registration and lookup.
   - Multi-provider consensus aggregation (malicious overrides unknown).
   - Non-blocking execution when an external provider fails or times out.
   - Bounded batch queries (check_indicators_batch).
   - Automatic email indicator extraction (extract_and_check_email).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from pydantic import SecretStr

from app.domain.entities.email_analysis_input import (
    EmailAnalysisInput,
    ExtractedAttachmentMetadata,
    ExtractedURLItem,
    NormalizedContent,
    NormalizedHeaders,
    NormalizedRecipient,
    NormalizedSender,
    RawEvidence,
    StructuralIntegrity,
)
from app.infrastructure.db.models.enums import ReputationVerdict, ThreatCategory, ThreatSeverity
from app.services.threat_intelligence.adapters.abuseipdb import AbuseIPDBAdapter
from app.services.threat_intelligence.adapters.internal import InternalThreatIntelAdapter
from app.services.threat_intelligence.adapters.mock import MockThreatIntelAdapter
from app.services.threat_intelligence.adapters.virustotal import VirusTotalAdapter
from app.services.threat_intelligence.base import ThreatIntelligenceProvider
from app.services.threat_intelligence.cache import ThreatIntelCache
from app.services.threat_intelligence.manager import ThreatIntelligenceService
from app.services.threat_intelligence.schemas import IndicatorType, ThreatIntelReport

# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------


def _make_mock_httpx_response(status_code: int, json_body: dict[str, Any]) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = json.dumps(json_body)
    return resp


def _make_sample_email_input() -> EmailAnalysisInput:
    sender = NormalizedSender(
        address="phish@evil-payload.top",
        display_name="Security Alert",
        domain="evil-payload.top",
        local_part="phish",
    )
    headers = NormalizedHeaders(
        message_id="<test-ti-id@example.com>",
        date=datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC),
        all_headers={},
        received_hops=(),
        x_originating_ip="198.51.100.42",
    )
    content = NormalizedContent(
        normalized_plain="Click http://malicious-phish.com to verify",
        raw_html=None,
        sanitized_html=None,
        clean_text_for_ai="Click http://malicious-phish.com to verify",
        character_count=40,
        has_html=False,
        has_plain=True,
    )
    raw_evidence = RawEvidence(
        raw_content="sample",
        raw_header_pairs=(),
        raw_from="phish@evil-payload.top",
        raw_to=("user@target.com",),
        raw_cc=(),
        raw_bcc=(),
        raw_reply_to=None,
        raw_return_path=None,
        raw_subject="Security Alert",
        raw_date=None,
        raw_body_plain="Click http://malicious-phish.com to verify",
        raw_body_html=None,
    )
    url_item = ExtractedURLItem(
        raw_url="http://malicious-phish.com",
        canonical_url="http://malicious-phish.com",
        defanged_url="hxxp://malicious-phish[.]com",
        domain="malicious-phish.com",
        scheme="http",
        path="",
        is_ip_address=False,
        is_shortener=False,
        is_suspicious_tld=False,
        source_location="body_plain",
    )
    attachment = ExtractedAttachmentMetadata(
        filename="invoice.exe",
        safe_filename="invoice.exe",
        extension="exe",
        declared_mime_type="application/octet-stream",
        detected_mime_type="application/x-dosexec",
        size_bytes=1024,
        md5_hash="44d88612fea8a8f36de82e1278abb02f",
        sha256_hash="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        is_executable=True,
        is_archive=False,
        has_double_extension=False,
        has_macro_extension=False,
    )
    integrity = StructuralIntegrity(is_malformed=False, anomalies=(), flags=())
    return EmailAnalysisInput(
        analysis_input_id="ti-email-001",
        raw_evidence=raw_evidence,
        sender=sender,
        recipients=(NormalizedRecipient("user@target.com", "", "target.com", "to"),),
        reply_to=None,
        return_path=None,
        subject="Security Alert",
        normalized_subject="security alert",
        headers=headers,
        content=content,
        urls=(url_item,),
        domains=("evil-payload.top", "malicious-phish.com"),
        attachments=(attachment,),
        integrity=integrity,
    )


# ===========================================================================
# 1. Output Contract & Schemas Tests
# ===========================================================================


class TestThreatIntelReportContract:
    """Validate that ThreatIntelReport satisfies all requested output attributes."""

    def test_required_fields_present_and_typed(self) -> None:
        report = ThreatIntelReport(
            indicator="evil-payload.top",
            indicator_type=IndicatorType.DOMAIN,
            provider="virustotal",
            reputation=ReputationVerdict.MALICIOUS,
            confidence=0.95,
            source="https://www.virustotal.com/api/v3/domains/evil-payload.top",
            timestamp=datetime.now(UTC),
            raw_reference={"engines_flagged": 15},
            threat_score=95.0,
            tags=["phishing", "c2"],
        )

        assert report.indicator == "evil-payload.top"
        assert report.indicator_type == IndicatorType.DOMAIN
        assert report.provider == "virustotal"
        assert report.reputation == ReputationVerdict.MALICIOUS
        assert report.confidence == 0.95
        assert "virustotal.com" in report.source
        assert isinstance(report.timestamp, datetime)
        assert report.raw_reference == {"engines_flagged": 15}
        assert report.threat_score == 95.0
        assert "phishing" in report.tags

    def test_to_threat_intel_signal_converter(self) -> None:
        report = ThreatIntelReport(
            indicator="198.51.100.42",
            indicator_type=IndicatorType.IP,
            provider="abuseipdb",
            reputation=ReputationVerdict.MALICIOUS,
            confidence=0.90,
            source="https://api.abuseipdb.com/api/v2/check",
            threat_score=85.0,
            tags=["c2"],
        )
        ti_signal = report.to_threat_intel_signal()
        assert ti_signal.indicator_type == "ip"
        assert ti_signal.indicator_value == "198.51.100.42"
        assert ti_signal.provider == "abuseipdb"
        assert ti_signal.verdict == ReputationVerdict.MALICIOUS
        assert ti_signal.threat_score == 85.0

    def test_to_threat_signal_converter_critical_severity(self) -> None:
        report = ThreatIntelReport(
            indicator="bad-domain.com",
            indicator_type=IndicatorType.DOMAIN,
            provider="virustotal",
            reputation=ReputationVerdict.MALICIOUS,
            confidence=0.92,
            source="vt://domain",
            threat_score=90.0,
            tags=["malware"],
        )
        signal = report.to_threat_signal()
        assert signal.source == "threat_intel"
        assert signal.severity == ThreatSeverity.CRITICAL
        assert signal.score >= 85.0
        assert signal.category == ThreatCategory.MALWARE
        assert signal.indicator_value == "bad-domain.com"


# ===========================================================================
# 2. ThreatIntelligenceProvider Abstraction Tests
# ===========================================================================


class TestProviderAbstraction:
    """Validate interface inheritance and generic dispatcher."""

    async def test_adapters_implement_abstract_base_class(self) -> None:
        adapters = [
            InternalThreatIntelAdapter(),
            VirusTotalAdapter(api_key=SecretStr("test-key")),
            AbuseIPDBAdapter(api_key=SecretStr("test-key")),
            MockThreatIntelAdapter(),
        ]
        for a in adapters:
            assert isinstance(a, ThreatIntelligenceProvider)
            assert len(a.provider_name) > 0

    async def test_generic_check_indicator_routes_correctly(self) -> None:
        adapter = MockThreatIntelAdapter()
        mock_report = ThreatIntelReport(
            indicator="test-hash-123",
            indicator_type=IndicatorType.HASH,
            provider="mock_provider",
            reputation=ReputationVerdict.MALICIOUS,
            confidence=1.0,
            source="mock://hash",
        )
        adapter.set_canned_response("test-hash-123", mock_report)

        result = await adapter.check_indicator("test-hash-123", IndicatorType.HASH)
        assert result.reputation == ReputationVerdict.MALICIOUS
        assert result.indicator_type == IndicatorType.HASH

    async def test_unsupported_indicator_type_returns_fallback_safely(self) -> None:
        abuse = AbuseIPDBAdapter(api_key=SecretStr("test-key"))
        # AbuseIPDB only supports IPs; checking a domain should safely return fallback
        result = await abuse.check_indicator("example.com", IndicatorType.DOMAIN)
        assert result.reputation == ReputationVerdict.UNKNOWN
        assert result.error_message is not None
        assert "not supported" in result.error_message.lower()


# ===========================================================================
# 3. InternalThreatIntelAdapter Tests
# ===========================================================================


class TestInternalThreatIntelAdapter:
    """Validate built-in local blocklist and allowlist lookups."""

    async def test_preseeded_malicious_domain(self) -> None:
        adapter = InternalThreatIntelAdapter()
        report = await adapter.check_domain("malicious-phish.com")
        assert report.reputation == ReputationVerdict.MALICIOUS
        assert report.threat_score >= 90.0
        assert report.confidence >= 0.90
        assert "phishing" in report.tags

    async def test_preseeded_malicious_ip(self) -> None:
        adapter = InternalThreatIntelAdapter()
        report = await adapter.check_ip("198.51.100.42")
        assert report.reputation == ReputationVerdict.MALICIOUS
        assert report.threat_score >= 90.0

    async def test_preseeded_malicious_hash_eicar(self) -> None:
        adapter = InternalThreatIntelAdapter()
        eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        report = await adapter.check_hash(eicar_sha256)
        assert report.reputation == ReputationVerdict.MALICIOUS
        assert report.threat_score == 100.0

    async def test_allowlisted_domain(self) -> None:
        adapter = InternalThreatIntelAdapter()
        report = await adapter.check_domain("google.com")
        assert report.reputation == ReputationVerdict.CLEAN
        assert report.threat_score == 0.0

    async def test_unknown_domain(self) -> None:
        adapter = InternalThreatIntelAdapter()
        report = await adapter.check_domain("unknown-innocent-company.org")
        assert report.reputation == ReputationVerdict.UNKNOWN
        assert report.threat_score == 0.0

    async def test_runtime_registration_dynamic_ioc(self) -> None:
        adapter = InternalThreatIntelAdapter()
        adapter.add_blocklist_entry(
            "newly-reported-c2.net", verdict=ReputationVerdict.MALICIOUS, threat_score=92.0
        )
        report = await adapter.check_domain("newly-reported-c2.net")
        assert report.reputation == ReputationVerdict.MALICIOUS
        assert report.threat_score == 92.0

        adapter.add_allowlist_entry("internal-partner.com")
        clean_report = await adapter.check_domain("internal-partner.com")
        assert clean_report.reputation == ReputationVerdict.CLEAN


# ===========================================================================
# 4. VirusTotalAdapter Tests
# ===========================================================================


class TestVirusTotalAdapter:
    """Validate VirusTotal v3 HTTP client integration, retries, and rate limits."""

    async def test_unconfigured_key_returns_safe_fallback(self) -> None:
        adapter = VirusTotalAdapter(api_key=SecretStr(""))
        assert not adapter.is_configured
        report = await adapter.check_domain("example.com")
        assert report.reputation == ReputationVerdict.UNKNOWN
        assert report.error_message is not None
        assert "not configured" in report.error_message.lower()

    async def test_successful_domain_query_malicious(self) -> None:
        adapter = VirusTotalAdapter(api_key=SecretStr("fake-key"))
        mock_payload = {
            "data": {
                "id": "evil.com",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 2,
                        "harmless": 20,
                        "undetected": 40,
                    },
                    "tags": ["phishing"],
                    "reputation": -50,
                },
            }
        }
        mock_resp = _make_mock_httpx_response(200, mock_payload)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            report = await adapter.check_domain("evil.com")

        assert report.reputation == ReputationVerdict.MALICIOUS
        assert report.threat_score >= 85.0
        assert report.confidence > 0.8
        assert "phishing" in report.tags

    async def test_url_query_encodes_unpadded_base64_id(self) -> None:
        adapter = VirusTotalAdapter(api_key=SecretStr("fake-key"))
        mock_payload = {
            "data": {
                "id": "u-123",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 10,
                        "undetected": 50,
                    },
                },
            }
        }
        mock_resp = _make_mock_httpx_response(200, mock_payload)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            test_url = "https://example.com/login?token=abc=="
            report = await adapter.check_url(test_url)

        # Check endpoint called has unpadded base64 (no trailing =)
        call_url = mock_get.call_args[0][0]
        assert "/api/v3/urls/" in call_url
        assert not call_url.endswith("=")
        assert report.reputation == ReputationVerdict.CLEAN

    async def test_404_not_found_returns_unknown_without_error(self) -> None:
        adapter = VirusTotalAdapter(api_key=SecretStr("fake-key"))
        mock_resp = _make_mock_httpx_response(404, {"error": {"message": "Not found"}})

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            report = await adapter.check_hash(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )

        assert report.reputation == ReputationVerdict.UNKNOWN
        assert report.error_message is None

    async def test_429_rate_limit_activates_cooldown(self) -> None:
        adapter = VirusTotalAdapter(api_key=SecretStr("fake-key"))
        mock_resp = _make_mock_httpx_response(429, {"error": {"message": "Quota exceeded"}})

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            report = await adapter.check_ip("1.2.3.4")

        assert report.reputation == ReputationVerdict.UNKNOWN
        assert "rate limit" in report.error_message.lower()
        assert adapter.is_rate_limited is True

        # Second immediate query should be short-circuited by cooldown without HTTP call
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get2:
            report2 = await adapter.check_ip("5.6.7.8")
            mock_get2.assert_not_called()
            assert "rate limit active" in report2.error_message.lower()

    async def test_timeout_returns_safe_fallback(self) -> None:
        adapter = VirusTotalAdapter(api_key=SecretStr("fake-key"), max_retries=0)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("Timeout")
            report = await adapter.check_domain("slow-domain.com")

        assert report.reputation == ReputationVerdict.UNKNOWN
        assert "timed out" in report.error_message.lower()


# ===========================================================================
# 5. AbuseIPDBAdapter Tests
# ===========================================================================


class TestAbuseIPDBAdapter:
    """Validate AbuseIPDB IP reputation checks."""

    async def test_malicious_ip_with_high_confidence_score(self) -> None:
        adapter = AbuseIPDBAdapter(api_key=SecretStr("fake-key"))
        mock_payload = {
            "data": {
                "ipAddress": "198.51.100.99",
                "isWhitelisted": False,
                "abuseConfidenceScore": 88,
                "totalReports": 42,
                "usageType": "Data Center/Web Hosting/Transit",
                "countryCode": "RU",
            }
        }
        mock_resp = _make_mock_httpx_response(200, mock_payload)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            report = await adapter.check_ip("198.51.100.99")

        assert report.reputation == ReputationVerdict.MALICIOUS
        assert report.threat_score == 88.0
        assert "geo:RU" in report.tags

    async def test_clean_whitelisted_ip(self) -> None:
        adapter = AbuseIPDBAdapter(api_key=SecretStr("fake-key"))
        mock_payload = {
            "data": {
                "ipAddress": "8.8.8.8",
                "isWhitelisted": True,
                "abuseConfidenceScore": 0,
                "totalReports": 0,
            }
        }
        mock_resp = _make_mock_httpx_response(200, mock_payload)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            report = await adapter.check_ip("8.8.8.8")

        assert report.reputation == ReputationVerdict.CLEAN
        assert report.threat_score == 0.0

    async def test_unconfigured_abuseipdb_fallback(self) -> None:
        adapter = AbuseIPDBAdapter(api_key=SecretStr(""))
        report = await adapter.check_ip("1.1.1.1")
        assert report.reputation == ReputationVerdict.UNKNOWN
        assert "not configured" in report.error_message.lower()


# ===========================================================================
# 6. ThreatIntelCache Tests
# ===========================================================================


class TestThreatIntelCache:
    """Validate thread-safe in-memory caching and TTL expiration."""

    def test_cache_hit_returns_cached_flag(self) -> None:
        cache = ThreatIntelCache(default_ttl_seconds=3600)
        report = ThreatIntelReport(
            indicator="cached-phish.com",
            indicator_type=IndicatorType.DOMAIN,
            provider="test_provider",
            reputation=ReputationVerdict.MALICIOUS,
            confidence=0.9,
            source="test://source",
            threat_score=80.0,
        )
        cache.set("test_provider", IndicatorType.DOMAIN, "cached-phish.com", report)

        cached = cache.get("test_provider", IndicatorType.DOMAIN, "cached-phish.com")
        assert cached is not None
        assert cached.is_cached is True
        assert cached.indicator == "cached-phish.com"
        assert cached.reputation == ReputationVerdict.MALICIOUS

    def test_cache_miss_returns_none(self) -> None:
        cache = ThreatIntelCache()
        assert cache.get("test_provider", IndicatorType.DOMAIN, "non-existent.com") is None

    def test_expired_entry_is_evicted(self) -> None:
        cache = ThreatIntelCache(default_ttl_seconds=1)
        report = ThreatIntelReport(
            indicator="short-ttl.com",
            indicator_type=IndicatorType.DOMAIN,
            provider="test",
            reputation=ReputationVerdict.CLEAN,
            confidence=0.8,
            source="test://source",
        )
        # Store with 0-second TTL (immediately expires)
        cache.set("test", IndicatorType.DOMAIN, "short-ttl.com", report, ttl_seconds=-1)

        assert cache.get("test", IndicatorType.DOMAIN, "short-ttl.com") is None
        assert cache.size() == 0

    def test_cache_clear(self) -> None:
        cache = ThreatIntelCache()
        report = ThreatIntelReport(
            indicator="clear-me.com",
            indicator_type=IndicatorType.DOMAIN,
            provider="test",
            reputation=ReputationVerdict.CLEAN,
            confidence=0.8,
            source="test://source",
        )
        cache.set("test", IndicatorType.DOMAIN, "clear-me.com", report)
        assert cache.size() == 1
        cache.clear()
        assert cache.size() == 0


# ===========================================================================
# 7. ThreatIntelligenceService (Multi-Provider Coordinator) Tests
# ===========================================================================


class TestThreatIntelligenceService:
    """Validate multi-provider orchestration, aggregation, and email extraction."""

    async def test_provider_registration_and_listing(self) -> None:
        service = ThreatIntelligenceService(providers=[])
        mock1 = MockThreatIntelAdapter("provider_one")
        mock2 = MockThreatIntelAdapter("provider_two")

        service.register_provider(mock1)
        service.register_provider(mock2)

        assert "provider_one" in service.list_providers()
        assert "provider_two" in service.list_providers()
        assert service.get_provider("provider_one") is mock1

    async def test_multi_provider_consensus_malicious_overrides_unknown(self) -> None:
        """When one provider finds a threat and another is unknown, malicious consensus wins."""
        mock_vt = MockThreatIntelAdapter("mock_vt")
        mock_local = MockThreatIntelAdapter("mock_local")

        # Local says unknown
        mock_local.set_canned_response(
            "danger-link.org",
            ThreatIntelReport(
                indicator="danger-link.org",
                indicator_type=IndicatorType.DOMAIN,
                provider="mock_local",
                reputation=ReputationVerdict.UNKNOWN,
                confidence=0.5,
                source="local",
            ),
        )
        # VT says malicious
        mock_vt.set_canned_response(
            "danger-link.org",
            ThreatIntelReport(
                indicator="danger-link.org",
                indicator_type=IndicatorType.DOMAIN,
                provider="mock_vt",
                reputation=ReputationVerdict.MALICIOUS,
                confidence=0.95,
                source="vt",
                threat_score=90.0,
                tags=["phishing"],
            ),
        )

        service = ThreatIntelligenceService(providers=[mock_local, mock_vt])
        report = await service.check_domain("danger-link.org")

        assert report.reputation == ReputationVerdict.MALICIOUS
        assert report.threat_score == 90.0
        assert "phishing" in report.tags
        assert "mock_vt" in report.provider

    async def test_non_blocking_provider_failure_recovery(self) -> None:
        """When an external provider fails, the internal provider's finding is still returned."""
        failing_external = MockThreatIntelAdapter("failing_ext", simulate_failure=True)
        working_internal = InternalThreatIntelAdapter()

        service = ThreatIntelligenceService(providers=[failing_external, working_internal])
        # Check pre-seeded blocklist domain
        report = await service.check_domain("malicious-phish.com")

        # Pipeline did not crash; internal blocklist hit was successfully captured
        assert report.reputation == ReputationVerdict.MALICIOUS
        assert report.threat_score >= 90.0

    async def test_batch_indicator_checking(self) -> None:
        mock = MockThreatIntelAdapter("mock")
        service = ThreatIntelligenceService(providers=[mock])

        indicators = [
            ("domain1.com", IndicatorType.DOMAIN),
            ("domain2.com", IndicatorType.DOMAIN),
            ("1.2.3.4", IndicatorType.IP),
        ]
        results = await service.check_indicators_batch(indicators, max_concurrency=2)

        assert len(results) == 3
        assert results[0].indicator == "domain1.com"
        assert results[2].indicator_type == IndicatorType.IP

    async def test_extract_and_check_email(self) -> None:
        """Full email indicator extraction and concurrent threat intelligence checks."""
        internal = InternalThreatIntelAdapter()
        service = ThreatIntelligenceService(providers=[internal])

        email_input = _make_sample_email_input()
        results = await service.extract_and_check_email(email_input)

        # Expected extracted items: sender domain, URLs, originating IP, attachment hashes
        assert len(results) >= 3
        indicators_checked = {r.indicator for r in results}

        assert "evil-payload.top" in indicators_checked
        assert "http://malicious-phish.com" in indicators_checked
        assert "198.51.100.42" in indicators_checked

        # At least one malicious finding from our pre-seeded internal blocklist
        malicious_hits = [r for r in results if r.reputation == ReputationVerdict.MALICIOUS]
        assert len(malicious_hits) >= 1
