"""Unit tests verifying security review implementations and defenses."""

from __future__ import annotations

import io
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from app.api.dependencies import get_current_user_claims, get_optional_user_claims, get_uow
from app.infrastructure.config.settings import Settings
from app.infrastructure.db.models.analysis import Analysis
from app.infrastructure.db.models.email import Email
from app.infrastructure.db.models.enums import AnalysisStatus, AnalysisVerdict, RiskLevel
from app.main import app
from app.services.security.ssrf_validator import SSRFProtection
from app.services.token_service import TokenClaims


# ===========================================================================
# 1. Security Headers Middleware Tests
# ===========================================================================


class TestSecurityHeaders:
    """Verify OWASP-compliant security headers are injected on all responses."""

    @pytest.mark.asyncio
    async def test_security_headers_present_on_response(self) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/v1/health")
            # 200 when live services up, 503 in mock/offline unit test mode
            assert resp.status_code in (200, 503)
            assert resp.headers["X-Content-Type-Options"] == "nosniff"
            assert resp.headers["X-Frame-Options"] == "DENY"
            assert resp.headers["X-XSS-Protection"] == "1; mode=block"
            assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
            assert "default-src 'none'" in resp.headers["Content-Security-Policy"]



# ===========================================================================
# 2. SSRF Protection Tests
# ===========================================================================


class TestSSRFProtection:
    """Verify comprehensive SSRF protection against internal networks and metadata."""

    @pytest.mark.parametrize(
        "prohibited_ip",
        [
            "127.0.0.1",
            "127.0.0.254",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.1.254",
            "169.254.169.254",  # AWS/GCP metadata
            "169.254.1.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
        ],
    )
    def test_prohibited_ips_detected(self, prohibited_ip: str) -> None:
        assert SSRFProtection.is_prohibited_ip(prohibited_ip) is True

    @pytest.mark.parametrize(
        "safe_ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
        ],
    )
    def test_public_safe_ips_allowed(self, safe_ip: str) -> None:
        assert SSRFProtection.is_prohibited_ip(safe_ip) is False

    @pytest.mark.parametrize(
        "malicious_url",
        [
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://10.0.0.5:8080/internal",
            "http://192.168.1.1/router",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_flushall",
            "ftp://anonymous@ftp.example.com",
            "http://localhost:8000/internal",
            "http://0x7f000001/admin",
        ],
    )
    def test_dangerous_urls_blocked_by_ssrf_validator(self, malicious_url: str) -> None:
        is_safe, reason = SSRFProtection.validate_url(malicious_url)
        assert is_safe is False
        assert reason is not None

    def test_safe_public_url_allowed(self) -> None:
        is_safe, reason = SSRFProtection.validate_url("https://www.example.com/login")
        assert is_safe is True
        assert reason is None

    def test_indicator_path_traversal_sanitized(self) -> None:
        dirty = "../../etc/passwd"
        clean = SSRFProtection.sanitize_indicator(dirty)
        assert ".." not in clean


# ===========================================================================
# 3. Settings Security Invariants
# ===========================================================================


class TestSettingsSecurity:
    """Verify production fail-fast on insecure JWT secrets."""

    def test_production_fails_on_default_insecure_jwt_secret(self) -> None:
        with pytest.raises(ValueError, match="JWT_SECRET_KEY must be set"):
            Settings(
                app_env="production",
                jwt_secret_key=SecretStr("CHANGE_ME_IN_PRODUCTION_USE_LONG_RANDOM_SECRET"),
            )

    def test_production_fails_on_short_jwt_secret(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            Settings(
                app_env="production",
                jwt_secret_key=SecretStr("short_secret"),
            )

    def test_production_succeeds_with_strong_secret(self) -> None:
        strong_secret = "a" * 64
        settings = Settings(
            app_env="production",
            jwt_secret_key=SecretStr(strong_secret),
        )
        assert settings.app_env == "production"


# ===========================================================================
# 4. IDOR Protection Tests
# ===========================================================================


class TestIDORProtection:
    """Verify cross-tenant data access is blocked on /analysis and /emails endpoints."""

    @pytest.mark.asyncio
    async def test_get_analysis_cross_tenant_denied(self) -> None:
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()
        analysis_id = uuid.uuid4()

        mock_analysis = MagicMock(spec=Analysis)
        mock_analysis.id = analysis_id
        mock_analysis.org_id = org_b  # Belongs to org_b

        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None
        mock_uow.analyses.get_with_full_details = AsyncMock(return_value=mock_analysis)

        # Caller claims belong to org_a
        caller_claims = TokenClaims(
            user_id=uuid.uuid4(),
            role="analyst",
            org_id=org_a,
            jti=uuid.uuid4(),
            token_type="access",
            exp=MagicMock(),
        )

        app.dependency_overrides[get_uow] = lambda: mock_uow
        app.dependency_overrides[get_optional_user_claims] = lambda: caller_claims

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.get(f"/api/v1/analysis/{analysis_id}")
                assert resp.status_code == 404  # Treated as opaque 404 for security
        finally:
            app.dependency_overrides.pop(get_uow, None)
            app.dependency_overrides.pop(get_optional_user_claims, None)

    @pytest.mark.asyncio
    async def test_get_email_cross_tenant_denied(self) -> None:
        org_a = uuid.uuid4()
        email_id = uuid.uuid4()

        mock_uow = MagicMock()
        mock_session = AsyncMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None
        mock_uow.session = mock_session

        # Return None when query filters by org_id != email.org_id
        mock_exec_result = MagicMock()
        mock_exec_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_exec_result)

        caller_claims = TokenClaims(
            user_id=uuid.uuid4(),
            role="analyst",
            org_id=org_a,
            jti=uuid.uuid4(),
            token_type="access",
            exp=MagicMock(),
        )

        app.dependency_overrides[get_uow] = lambda: mock_uow
        app.dependency_overrides[get_optional_user_claims] = lambda: caller_claims

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.get(f"/api/v1/emails/{email_id}")
                assert resp.status_code == 404
        finally:
            app.dependency_overrides.pop(get_uow, None)
            app.dependency_overrides.pop(get_optional_user_claims, None)


# ===========================================================================
# 5. File Upload Security Tests
# ===========================================================================


class TestFileUploadSecurity:
    """Verify file upload size caps, MIME guards, and path traversal defenses."""

    @pytest.mark.asyncio
    async def test_oversized_eml_upload_rejected(self) -> None:
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                # 26 MB dummy payload (>25 MB limit)
                oversized_bytes = b"X" * (26 * 1024 * 1024)
                files = {"eml_file": ("test.eml", io.BytesIO(oversized_bytes), "message/rfc822")}
                resp = await client.post("/api/v1/emails/analyze/upload", files=files)
                assert resp.status_code == 400
                assert "25 MB" in resp.json()["error"]["message"]
        finally:
            app.dependency_overrides.pop(get_uow, None)

    @pytest.mark.asyncio
    async def test_invalid_mime_type_upload_rejected(self) -> None:
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                files = {
                    "eml_file": ("malware.exe", io.BytesIO(b"MZ\x90\x00"), "application/x-dosexec")
                }
                resp = await client.post("/api/v1/emails/analyze/upload", files=files)
                assert resp.status_code == 400
                assert "Invalid file type" in resp.json()["error"]["message"]
        finally:
            app.dependency_overrides.pop(get_uow, None)
