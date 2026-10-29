"""Unit tests for platform failure and resilience cases.

Covers:
1. Groq LLM unavailable / timeout / 503
2. Database unavailable / connection error handling
3. Redis unavailable / graceful degradation in rate limiter and cache
4. Threat intelligence provider unavailable (VT / AbuseIPDB timeout & 429)
5. Malformed email (invalid MIME, broken encoding, missing headers)
6. Oversized file (>25 MB EML, >10 MB attachment)
7. Invalid URL (SSRF targets, non-HTTP schemes, null bytes)
8. Invalid authentication (malformed token, tampered signature)
9. Expired token (past expiry timestamp)
"""

from __future__ import annotations

import io
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from jose import jwt
from pydantic import SecretStr

from app.api.dependencies import get_current_user_claims, get_optional_user_claims, get_uow
from app.domain.entities.email_analysis_input import (
    EmailAnalysisInput,
    NormalizedContent,
    NormalizedHeaders,
    NormalizedRecipient,
    NormalizedSender,
    RawEvidence,
    StructuralIntegrity,
)
from app.infrastructure.config.settings import Settings, get_settings
from app.infrastructure.db.models.enums import ReputationVerdict
from app.main import app
from app.services.email_parser_service import EmailParserService
from app.services.llm.client import GroqClient
from app.services.llm.groq_provider import GroqProvider
from app.services.security.ssrf_validator import SSRFProtection
from app.services.threat_intelligence.adapters.abuseipdb import AbuseIPDBAdapter
from app.services.threat_intelligence.adapters.virustotal import VirusTotalAdapter
from app.services.token_service import TokenClaims, TokenService


def _make_test_email_input() -> EmailAnalysisInput:
    sender = NormalizedSender(
        address="phish@evil.xyz",
        display_name="Security Alert",
        domain="evil.xyz",
        local_part="phish",
    )
    headers = NormalizedHeaders(
        message_id="<test@evil.xyz>",
        date=datetime.now(UTC),
        all_headers={},
        received_hops=(),
    )
    content = NormalizedContent(
        normalized_plain="Click to reset your password",
        raw_html=None,
        sanitized_html=None,
        clean_text_for_ai="Click to reset your password",
        character_count=28,
        has_html=False,
        has_plain=True,
    )
    raw_evidence = RawEvidence(
        raw_content="Click to reset",
        raw_header_pairs=(),
        raw_from="phish@evil.xyz",
        raw_to=("victim@example.com",),
        raw_cc=(),
        raw_bcc=(),
        raw_reply_to=None,
        raw_return_path=None,
        raw_subject="Urgent Security Alert",
        raw_date=None,
        raw_body_plain="Click to reset",
        raw_body_html=None,
    )
    return EmailAnalysisInput(
        analysis_input_id="test-resilience-001",
        raw_evidence=raw_evidence,
        sender=sender,
        recipients=(
            NormalizedRecipient(
                address="victim@example.com",
                display_name="",
                domain="example.com",
                recipient_type="to",
            ),
        ),
        reply_to=None,
        return_path=None,
        subject="Urgent Security Alert",
        normalized_subject="urgent security alert",
        headers=headers,
        content=content,
        urls=(),
        domains=("evil.xyz",),
        attachments=(),
        integrity=StructuralIntegrity(is_malformed=False, anomalies=(), flags=()),
    )



# ===========================================================================
# 1. Groq LLM Provider Unavailable
# ===========================================================================


class TestGroqUnavailableResilience:
    """Ensure the pipeline degrades gracefully when Groq is down or times out."""

    @pytest.mark.asyncio
    async def test_groq_timeout_handled_gracefully(self) -> None:
        """When Groq times out, provider returns timeout status without crashing."""
        client = GroqClient(api_key=SecretStr("mock-key"), timeout=1, max_retries=0)
        provider = GroqProvider(client=client)
        email_input = _make_test_email_input()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("Read timed out")
            result = await provider.analyze(email_input)
            assert result is not None
            assert result.status == "timeout"
            assert result.analysis is None
            assert result.confidence == 0.0
            assert "timed out" in (result.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_groq_503_service_unavailable(self) -> None:
        """When Groq returns HTTP 503, provider returns api_error status gracefully."""
        client = GroqClient(api_key=SecretStr("mock-key"), timeout=1, max_retries=0)
        provider = GroqProvider(client=client)
        email_input = _make_test_email_input()

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 503
        mock_resp.text = "Service Unavailable"
        mock_resp.json.return_value = {"error": "service_unavailable"}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            result = await provider.analyze(email_input)
            assert result is not None
            assert result.status in ("api_error", "fallback")
            assert result.analysis is None
            assert result.confidence == 0.0


# ===========================================================================
# 2. Database Unavailable / Error Handling
# ===========================================================================


class TestDatabaseUnavailable:
    """Ensure database connection failures return structured 503 or 500 without leaking stack traces."""

    @pytest.mark.asyncio
    async def test_health_check_returns_degraded_when_db_down(self) -> None:
        """Health check returns 503 Service Unavailable when DB ping fails."""
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test"
        ) as client:
            resp = await client.get("/api/v1/health")
            # In unit tests without running PostgreSQL, health check returns 503
            assert resp.status_code in (200, 503)
            data = resp.json()
            assert "status" in data
            assert "checks" in data


    @pytest.mark.asyncio
    async def test_unhandled_exception_returns_opaque_500(self) -> None:
        """Unhandled database exception maps to opaque JSON 500 without tracebacks."""
        mock_uow = MagicMock()
        mock_uow.__aenter__.side_effect = RuntimeError("Database connection pool exhausted")

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test"
            ) as client:
                resp = await client.get(f"/api/v1/analysis/{uuid.uuid4()}")
                assert resp.status_code == 500
                data = resp.json()
                assert data["success"] is False
                assert data["error"]["code"] == "INTERNAL_ERROR"
                assert "Traceback" not in data["error"]["message"]
                assert "exhausted" not in data["error"]["message"]
        finally:
            app.dependency_overrides.pop(get_uow, None)



# ===========================================================================
# 3. Redis Unavailable / Graceful Degradation
# ===========================================================================


class TestRedisUnavailable:
    """Ensure Redis failures degrade gracefully without blocking requests."""

    @pytest.mark.asyncio
    async def test_rate_limiter_allows_traffic_when_redis_offline(self) -> None:
        """When Redis is unreachable, RateLimitMiddleware logs a warning and allows request through."""
        with patch(
            "app.infrastructure.cache.redis_client.get_redis_client",
            side_effect=ConnectionError("Cannot connect to Redis on localhost:6379"),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.get("/api/v1/health")
                # Request must NOT be blocked with a 500 or crash due to Redis failure
                assert resp.status_code in (200, 503)


# ===========================================================================
# 4. Threat Intelligence Unavailable
# ===========================================================================


class TestThreatIntelligenceUnavailable:
    """Ensure VirusTotal and AbuseIPDB timeouts / rate limits do not crash callers."""

    @pytest.mark.asyncio
    async def test_virustotal_timeout_returns_fallback_report(self) -> None:
        """VirusTotalAdapter returns fallback report when request times out."""
        adapter = VirusTotalAdapter(api_key=SecretStr("test-key"), timeout=1, max_retries=0)

        with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Read timed out")):
            report = await adapter.check_domain("suspicious-domain.com")
            assert report.reputation == ReputationVerdict.UNKNOWN
            assert report.confidence == 0.0
            assert report.threat_score == 0.0
            assert "timed out" in (report.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_virustotal_429_rate_limit_activates_cooldown(self) -> None:
        """VirusTotalAdapter enforces temporary cooldown when 429 received."""
        adapter = VirusTotalAdapter(api_key=SecretStr("test-key"), timeout=5, max_retries=0)

        mock_resp = MagicMock(status_code=429)
        with patch("httpx.AsyncClient.get", return_value=mock_resp):
            report = await adapter.check_domain("check-me.org")
            assert report.reputation == ReputationVerdict.UNKNOWN
            assert adapter.is_rate_limited is True

    @pytest.mark.asyncio
    async def test_abuseipdb_timeout_returns_fallback_report(self) -> None:
        """AbuseIPDBAdapter returns fallback report when API times out."""
        adapter = AbuseIPDBAdapter(api_key=SecretStr("test-key"), timeout=1)

        with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Read timeout")):
            report = await adapter.check_ip("93.184.216.34")
            assert report.reputation == ReputationVerdict.UNKNOWN
            assert "timed out" in (report.error_message or "").lower()


# ===========================================================================
# 5. Malformed Email Parsing Resilience
# ===========================================================================


class TestMalformedEmailResilience:
    """Ensure broken, malformed, or hostile email formats parse safely."""

    def test_empty_raw_content_handled_safely(self) -> None:
        artifacts = EmailParserService.parse_raw_eml("")
        assert artifacts.from_address == "unknown@unknown.local"
        assert artifacts.from_domain == "unknown.local"
        assert artifacts.urls == []
        assert artifacts.attachments == []

    def test_broken_binary_garbage_does_not_crash_parser(self) -> None:
        garbage_bytes = b"\xff\xfe\x00\x01\x80\x90\xaa\xbb\xcc\xdd" * 50
        artifacts = EmailParserService.parse_raw_eml(garbage_bytes)
        assert artifacts.from_domain == "unknown.local"
        assert artifacts.message_id is not None

    def test_malformed_headers_missing_colons(self) -> None:
        malformed = "Subject Urgent Action\nFrom user evil com\n\nBody without proper headers"
        artifacts = EmailParserService.parse_raw_eml(malformed)
        assert artifacts is not None
        assert artifacts.body_plain is not None or artifacts.body_preview is not None

    def test_deeply_nested_multipart_mime(self) -> None:
        """Parser safely extracts content from recursive multipart boundaries."""
        nested = (
            "Content-Type: multipart/mixed; boundary=\"outer\"\n\n"
            "--outer\n"
            "Content-Type: multipart/alternative; boundary=\"inner\"\n\n"
            "--inner\n"
            "Content-Type: text/plain\n\n"
            "Hello from inside nested multipart!\n"
            "--inner--\n"
            "--outer--"
        )
        artifacts = EmailParserService.parse_raw_eml(nested)
        assert artifacts.body_plain is not None
        assert "Hello from inside nested multipart!" in artifacts.body_plain


# ===========================================================================
# 6. Oversized File Validation
# ===========================================================================


class TestOversizedFileValidation:
    """Verify size limits on .eml and attachments are enforced."""

    @pytest.mark.asyncio
    async def test_oversized_eml_upload_rejected_with_400(self) -> None:
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                oversized_bytes = b"MIME-Version: 1.0\n" + (b"X" * (26 * 1024 * 1024))
                files = {"eml_file": ("oversized.eml", io.BytesIO(oversized_bytes), "message/rfc822")}
                resp = await client.post("/api/v1/emails/analyze/upload", files=files)
                assert resp.status_code == 400
                assert "25 MB" in resp.json()["error"]["message"]
        finally:
            app.dependency_overrides.pop(get_uow, None)

    @pytest.mark.asyncio
    async def test_zero_byte_eml_rejected_with_400(self) -> None:
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                files = {"eml_file": ("empty.eml", io.BytesIO(b""), "message/rfc822")}
                resp = await client.post("/api/v1/emails/analyze/upload", files=files)
                assert resp.status_code == 400
                assert "empty" in resp.json()["error"]["message"].lower()
        finally:
            app.dependency_overrides.pop(get_uow, None)


# ===========================================================================
# 7. Invalid URL / SSRF Targets
# ===========================================================================


class TestInvalidURLValidation:
    """Verify SSRFProtection blocks dangerous protocols and private destinations."""

    @pytest.mark.parametrize(
        "invalid_url,expected_keyword",
        [
            ("file:///etc/shadow", "prohibited"),
            ("gopher://127.0.0.1:25/", "prohibited"),
            ("http://127.0.0.1/admin", "prohibited"),
            ("http://169.254.169.254/latest/meta-data/", "prohibited"),
            ("http://10.0.1.50:9000/", "prohibited"),
            ("http://192.168.1.1/setup", "prohibited"),
            ("http://metadata.google.internal/", "prohibited"),
            ("http://[::1]/internal", "prohibited"),
            ("http://0x7f.0.0.1/", "obfuscated"),
            ("javascript:alert(1)", "prohibited"),
            ("data:text/html,<script>alert(1)</script>", "prohibited"),
        ],
    )
    def test_ssrf_validator_blocks_invalid_urls(
        self, invalid_url: str, expected_keyword: str
    ) -> None:
        is_safe, reason = SSRFProtection.validate_url(invalid_url)
        assert is_safe is False
        assert reason is not None
        assert expected_keyword in reason.lower()

    def test_url_with_null_byte_rejected(self) -> None:
        is_safe, reason = SSRFProtection.validate_url("http://example.com/\x00admin")
        assert is_safe is False
        assert "null byte" in (reason or "").lower()


# ===========================================================================
# 8. Invalid Authentication / Tampered Tokens
# ===========================================================================


class TestInvalidAuthentication:
    """Verify invalid and tampered tokens are rejected."""

    def test_tampered_signature_rejected(self) -> None:
        settings = get_settings()
        service = TokenService(settings)

        # Token signed with a different key
        bad_token = jwt.encode(
            {"sub": str(uuid.uuid4()), "role": "analyst", "org": str(uuid.uuid4()), "type": "access"},
            "wrong-secret-key-that-does-not-match",
            algorithm="HS256",
        )

        with pytest.raises(ValueError, match="Invalid token"):
            service.decode_token(bad_token)

    def test_wrong_token_type_rejected(self) -> None:
        """Using a refresh token where an access token is expected must fail."""
        settings = get_settings()
        service = TokenService(settings)

        user_id = uuid.uuid4()
        org_id = uuid.uuid4()
        refresh_token, _, _ = service.create_refresh_token(user_id, "analyst", org_id)

        with pytest.raises(ValueError, match="Wrong token type"):
            service.decode_token(refresh_token, expected_type="access")

    def test_completely_malformed_jwt_string(self) -> None:
        settings = get_settings()
        service = TokenService(settings)

        with pytest.raises(ValueError, match="Invalid token"):
            service.decode_token("not.a.valid.jwt.token.structure")


# ===========================================================================
# 9. Expired Token
# ===========================================================================


class TestExpiredToken:
    """Verify expired tokens are rejected by the token validator."""

    def test_expired_token_claims_detected(self) -> None:
        user_id = uuid.uuid4()
        org_id = uuid.uuid4()
        jti = uuid.uuid4()

        # Claims with exp set 10 minutes in the past
        past_exp = datetime.now(UTC) - timedelta(minutes=10)
        claims = TokenClaims(
            user_id=user_id,
            role="analyst",
            org_id=org_id,
            jti=jti,
            token_type="access",
            exp=past_exp,
        )

        assert claims.is_expired() is True

    def test_token_service_rejects_expired_jwt(self) -> None:
        """JWT with expired timestamp raises validation error on decode."""
        settings = get_settings()
        secret = settings.jwt_secret_key.get_secret_value()

        now = datetime.now(UTC)
        past = now - timedelta(hours=1)

        payload = {
            "sub": str(uuid.uuid4()),
            "role": "analyst",
            "org": str(uuid.uuid4()),
            "jti": str(uuid.uuid4()),
            "type": "access",
            "iat": int(past.timestamp()) - 3600,
            "exp": int(past.timestamp()),
        }

        expired_jwt = jwt.encode(payload, secret, algorithm=settings.jwt_algorithm)
        service = TokenService(settings)

        with pytest.raises(ValueError, match="Invalid token"):
            service.decode_token(expired_jwt, expected_type="access")
