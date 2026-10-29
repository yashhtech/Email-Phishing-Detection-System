"""Unit tests for the Security Incident Reporting module, API router, and sanitization."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient

from app.api.dependencies import get_uow
from app.api.schemas.report import (
    AnalysisReportResponse,
    ReportClassification,
    ReportEmailMetadata,
    ReportEvidenceItem,
    ReportGroqAnalysis,
    ReportMLAnalysis,
    ReportRiskScore,
    ReportSecuritySignal,
    ReportThreatIntelligence,
    ReportTimestamps,
)
from app.infrastructure.db.models.enums import AuditAction
from app.main import app
from app.services.report_service import ReportService, sanitize_value
from app.services.token_service import TokenClaims

# ===========================================================================
# 1. Report Schema & Sanitization Tests
# ===========================================================================


class TestReportSanitization:
    """Verify that secrets, tokens, and internal API keys are strictly excluded or redacted."""

    def test_sanitize_value_redacts_sensitive_keys(self) -> None:
        data = {
            "normal_field": "safe_value",
            "api_key": "secret_key_12345",
            "bearer_token": "Bearer token_abc123",
            "nested": {
                "groq_api_key": "gsk_abcdef1234567890abcdef12345",
                "safe_nested": 42,
            },
        }
        sanitized = sanitize_value(data)
        assert sanitized["normal_field"] == "safe_value"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["bearer_token"] == "[REDACTED]"
        assert sanitized["nested"]["groq_api_key"] == "[REDACTED]"
        assert sanitized["nested"]["safe_nested"] == 42

    def test_sanitize_value_redacts_api_key_patterns_in_strings(self) -> None:
        raw_string = "Request failed with key: gsk_1234567890abcdef1234567890"
        sanitized = sanitize_value(raw_string)
        assert "gsk_" not in sanitized
        assert "[REDACTED_KEY]" in sanitized

    def test_sanitize_value_leaves_safe_data_untouched(self) -> None:
        safe_list = ["phishing", "domain_spoofing", 100, 3.14]
        assert sanitize_value(safe_list) == safe_list


class TestReportSchemas:
    """Validate Pydantic models for Report contracts."""

    def test_analysis_report_response_serialization(self) -> None:
        now = datetime.now(UTC)
        report_id = uuid.uuid4()
        analysis_id = uuid.uuid4()
        org_id = uuid.uuid4()

        report = AnalysisReportResponse(
            report_id=report_id,
            analysis_id=analysis_id,
            org_id=org_id,
            org_name="Enterprise Security Tenant",
            engine_version="1.0.0",
            scoring_version="1.0",
            classification=ReportClassification(
                verdict="malicious",
                status="completed",
                primary_attack_type="credential_harvesting",
                severity="critical",
                confidence=0.98,
            ),
            risk_score=ReportRiskScore(
                overall_risk_score=92,
                risk_level="critical",
                composite_score=92,
                scoring_version="1.0",
                spf_subscore=10.0,
                dkim_subscore=10.0,
                dmarc_subscore=15.0,
                ml_subscore=25.0,
                url_subscore=20.0,
                attachment_subscore=0.0,
                sender_reputation_subscore=12.0,
            ),
            email_metadata=ReportEmailMetadata(
                email_id=str(uuid.uuid4()),
                message_id="<test-msg@attacker.net>",
                from_address="billing@attacker-domain.com",
                from_domain="attacker-domain.com",
                to_addresses=["ceo@victim.org"],
                subject="Urgent: Outstanding Invoice #99812",
                received_at=now,
                has_attachments=False,
                attachment_count=0,
                url_count=2,
                spf_status="fail",
                dkim_status="none",
                dmarc_status="fail",
            ),
            security_signals=[
                ReportSecuritySignal(
                    id=str(uuid.uuid4()),
                    signal_type="dmarc_failure",
                    category="authentication",
                    severity="critical",
                    attack_type="spoofing",
                    confidence=1.0,
                    source="dmarc_analyzer",
                    title="DMARC Policy Rejection",
                    description="Sender domain failed alignment and policy mandates quarantine/reject.",
                )
            ],
            ml_analysis=ReportMLAnalysis(
                model_name="ensemble-xgboost-bert",
                model_version="v2.4",
                classification="phishing",
                confidence=0.96,
                phishing_probability=0.94,
                spam_probability=0.05,
                malware_probability=0.01,
                latency_ms=120,
            ),
            groq_analysis=ReportGroqAnalysis(
                model_name="llama-3.3-70b-versatile",
                prompt_version="v1.2",
                threat_narrative="Email impersonates accounts receivable demanding wire transfer.",
                executive_summary="Critical credential harvesting campaign targeting finance.",
                recommended_action="quarantine",
                reasoning="Language uses high urgency, false invoice references, and suspicious domain.",
                extracted_iocs=[{"type": "url", "value": "http://evil-billing-portal.com"}],
                safety_passed=True,
                confidence_score=0.95,
                latency_ms=850,
            ),
            threat_intelligence=[
                ReportThreatIntelligence(
                    indicator_type="domain",
                    indicator_value="attacker-domain.com",
                    provider="virustotal",
                    reputation="malicious",
                    threat_score=85,
                    tags=["phishing", "fast-flux"],
                    last_checked_at=now,
                )
            ],
            evidence=[
                ReportEvidenceItem(
                    title="DMARC Policy Rejection",
                    severity="critical",
                    source="dmarc_analyzer",
                    category="authentication",
                    attack_type="spoofing",
                    description="Sender domain failed alignment and policy mandates quarantine/reject.",
                    confidence=1.0,
                    why_it_matters="Email sender authentication failed.",
                )
            ],
            timestamps=ReportTimestamps(
                email_received_at=now,
                analysis_started_at=now,
                analysis_completed_at=now,
                report_generated_at=now,
                duration_ms=1150,
            ),
            generated_by="analyst@victim.org",
        )

        dumped = report.model_dump(mode="json")
        assert dumped["report_id"] == str(report_id)
        assert dumped["classification"]["verdict"] == "malicious"
        assert dumped["risk_score"]["overall_risk_score"] == 92
        assert dumped["engine_version"] == "1.0.0"
        assert dumped["scoring_version"] == "1.0"
        assert len(dumped["security_signals"]) == 1
        assert len(dumped["evidence"]) == 1
        assert len(dumped["threat_intelligence"]) == 1
        assert dumped["ml_analysis"]["classification"] == "phishing"
        assert dumped["groq_analysis"]["model_name"] == "llama-3.3-70b-versatile"

    def test_render_html_report_contains_all_sections_and_no_secrets(self) -> None:
        now = datetime.now(UTC)
        report = AnalysisReportResponse(
            report_id=uuid.uuid4(),
            analysis_id=uuid.uuid4(),
            org_id=uuid.uuid4(),
            org_name="Acme Corp",
            engine_version="1.0.0",
            scoring_version="1.0",
            classification=ReportClassification(
                verdict="malicious",
                status="completed",
                primary_attack_type="credential_harvesting",
                severity="critical",
                confidence=0.98,
            ),
            risk_score=ReportRiskScore(
                overall_risk_score=88,
                risk_level="critical",
                composite_score=88,
                scoring_version="1.0",
            ),
            email_metadata=ReportEmailMetadata(
                email_id=str(uuid.uuid4()),
                from_address="phish@evil.com",
                subject="Verify Your Account Immediately",
                received_at=now,
            ),
            security_signals=[],
            ml_analysis=ReportMLAnalysis(
                model_name="xgboost-classifier",
                model_version="v1.0",
                classification="phishing",
                confidence=0.92,
                phishing_probability=0.91,
                spam_probability=0.08,
                malware_probability=0.01,
            ),
            groq_analysis=ReportGroqAnalysis(
                model_name="llama-3.3-70b-versatile",
                prompt_version="v1.0",
                threat_narrative="Deceptive account lock narrative.",
                recommended_action="quarantine",
                confidence_score=0.94,
            ),
            threat_intelligence=[],
            evidence=[],
            timestamps=ReportTimestamps(report_generated_at=now),
            generated_by="analyst@acme.com",
        )

        html_out = ReportService.render_html(report)
        assert "<!DOCTYPE html>" in html_out
        assert "Email Security Incident Report" in html_out
        assert "Engine v1.0.0 (Scoring v1.0)" in html_out
        assert "Verdict: MALICIOUS" in html_out
        assert "phish@evil.com" in html_out
        assert "Verify Your Account Immediately" in html_out
        assert "xgboost-classifier" in html_out
        assert "llama-3.3-70b-versatile" in html_out
        assert "@media print" in html_out
        # Assert NO secret patterns
        assert "gsk_" not in html_out
        assert "secret_key" not in html_out


# ===========================================================================
# 2. Reports API Endpoints & Authorization Tests
# ===========================================================================


class TestReportsAPI:
    """Test API endpoint responses, format selection, tenant authorization, and audit logging."""

    @pytest.mark.asyncio
    async def test_generate_report_not_found(self, async_client: AsyncClient) -> None:
        """404 returned when analysis does not exist."""
        non_existent_id = uuid.uuid4()
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None
        mock_analyses_repo = AsyncMock()
        mock_analyses_repo.get_with_full_details.return_value = None
        mock_uow.analyses = mock_analyses_repo

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            response = await async_client.get(f"/api/v1/reports/analysis/{non_existent_id}")
            assert response.status_code == 404
        finally:
            app.dependency_overrides.pop(get_uow, None)

    @pytest.mark.asyncio
    async def test_generate_report_authorization_tenant_mismatch(
        self, async_client: AsyncClient
    ) -> None:
        """403 Forbidden returned when user attempts to access report for another tenant."""
        analysis_id = uuid.uuid4()
        analysis_org_id = uuid.uuid4()
        caller_org_id = uuid.uuid4()  # Mismatched organization!

        mock_analysis = MagicMock()
        mock_analysis.id = analysis_id
        mock_analysis.org_id = analysis_org_id

        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None
        mock_analyses_repo = AsyncMock()
        mock_analyses_repo.get_with_full_details.return_value = mock_analysis
        mock_uow.analyses = mock_analyses_repo
        mock_users_repo = AsyncMock()
        mock_users_repo.get_by_id.return_value = None
        mock_uow.users = mock_users_repo

        # Token claims for caller with caller_org_id
        caller_claims = TokenClaims(
            user_id=uuid.uuid4(),
            role="security_analyst",
            org_id=caller_org_id,
            jti=uuid.uuid4(),
            token_type="access",
            exp=datetime.now(UTC),
        )

        from app.api.dependencies import get_optional_user_claims

        app.dependency_overrides[get_uow] = lambda: mock_uow
        app.dependency_overrides[get_optional_user_claims] = lambda: caller_claims

        try:
            response = await async_client.get(f"/api/v1/reports/analysis/{analysis_id}")
            assert response.status_code == 403
            assert "another organization" in response.text
        finally:
            app.dependency_overrides.pop(get_uow, None)
            app.dependency_overrides.pop(get_optional_user_claims, None)

    @pytest.mark.asyncio
    async def test_generate_report_json_success_with_audit_log(
        self, async_client: AsyncClient
    ) -> None:
        """Verify successful JSON report generation and audit log entry insertion."""
        analysis_id = uuid.uuid4()
        org_id = uuid.uuid4()
        user_id = uuid.uuid4()
        now = datetime.now(UTC)

        # Build mock analysis
        mock_email = MagicMock()
        mock_email.id = uuid.uuid4()
        mock_email.message_id = "<msg@test.local>"
        mock_email.from_address = "sender@domain.com"
        mock_email.from_domain = "domain.com"
        mock_email.to_addresses = ["user@domain.com"]
        mock_email.cc_addresses = []
        mock_email.reply_to = None
        mock_email.subject = "Test Security Subject"
        mock_email.received_at = now
        mock_email.has_attachments = False
        mock_email.attachment_count = 0
        mock_email.header = None
        mock_email.attachments = []
        mock_email.urls = []

        mock_risk_score = MagicMock()
        mock_risk_score.overall_risk_score = 75
        mock_risk_score.composite_score = 75
        mock_risk_score.scoring_version = "1.0"
        mock_risk_score.spf_subscore = 0.0
        mock_risk_score.dkim_subscore = 0.0
        mock_risk_score.dmarc_subscore = 0.0
        mock_risk_score.ml_subscore = 40.0
        mock_risk_score.url_subscore = 25.0
        mock_risk_score.attachment_subscore = 0.0
        mock_risk_score.sender_reputation_subscore = 10.0
        mock_risk_score.factor_breakdown = []

        mock_analysis = MagicMock()
        mock_analysis.id = analysis_id
        mock_analysis.org_id = org_id
        mock_analysis.email = mock_email
        mock_analysis.risk_score = mock_risk_score
        mock_analysis.ml_prediction = None
        mock_analysis.llm_analysis = None
        mock_analysis.threat_signals = []
        mock_analysis.threat_intel_results = []
        mock_analysis.overall_risk_score = 75
        from app.infrastructure.db.models.enums import AnalysisStatus, AnalysisVerdict, RiskLevel
        mock_analysis.risk_level = RiskLevel.HIGH
        mock_analysis.verdict = AnalysisVerdict.MALICIOUS
        mock_analysis.status = AnalysisStatus.COMPLETE
        mock_analysis.started_at = now
        mock_analysis.completed_at = now
        mock_analysis.duration_ms = 1200

        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None
        mock_analyses_repo = AsyncMock()
        mock_analyses_repo.get_with_full_details.return_value = mock_analysis
        mock_uow.analyses = mock_analyses_repo

        mock_audit_repo = AsyncMock()
        mock_uow.audit_logs = mock_audit_repo
        mock_uow.commit = AsyncMock()

        # Mock org query
        mock_session = AsyncMock()
        mock_exec_res = MagicMock()
        mock_exec_res.scalar_one_or_none.return_value = "Test Enterprise Org"
        mock_session.execute.return_value = mock_exec_res
        mock_uow.session = mock_session

        mock_users_repo = AsyncMock()
        mock_user = MagicMock()
        mock_user.email = "analyst@security.local"
        mock_users_repo.get_by_id.return_value = mock_user
        mock_uow.users = mock_users_repo

        caller_claims = TokenClaims(
            user_id=user_id,
            role="security_analyst",
            org_id=org_id,
            jti=uuid.uuid4(),
            token_type="access",
            exp=datetime.now(UTC),
        )

        from app.api.dependencies import get_optional_user_claims

        app.dependency_overrides[get_uow] = lambda: mock_uow
        app.dependency_overrides[get_optional_user_claims] = lambda: caller_claims

        try:
            response = await async_client.get(
                f"/api/v1/reports/analysis/{analysis_id}?format=json"
            )
            assert response.status_code == 200
            data = response.json()

            # Verify report contents
            assert data["analysis_id"] == str(analysis_id)
            assert data["org_name"] == "Test Enterprise Org"
            assert data["classification"]["verdict"] == "malicious"
            assert data["risk_score"]["overall_risk_score"] == 75
            assert data["email_metadata"]["from_address"] == "sender@domain.com"
            assert data["engine_version"] == "1.0.0"
            assert data["scoring_version"] == "1.0"
            assert "X-Report-ID" in response.headers

            # Verify audit logging was invoked
            assert mock_audit_repo.create.called
            audit_call_arg = mock_audit_repo.create.call_args[0][0]
            assert audit_call_arg.event_type == "ANALYSIS_REPORT_GENERATED"
            assert audit_call_arg.action == AuditAction.EXPORT
            assert audit_call_arg.resource_type == "analysis_report"
            assert audit_call_arg.resource_id == str(analysis_id)
            assert audit_call_arg.actor_user_id == user_id
            assert audit_call_arg.metadata_payload["format"] == "json"
            assert mock_uow.commit.called
        finally:
            app.dependency_overrides.pop(get_uow, None)
            app.dependency_overrides.pop(get_optional_user_claims, None)

    @pytest.mark.asyncio
    async def test_generate_report_html_format(
        self, async_client: AsyncClient
    ) -> None:
        """Verify report returns clean text/html when format=html is requested."""
        analysis_id = uuid.uuid4()
        org_id = uuid.uuid4()
        now = datetime.now(UTC)

        mock_email = MagicMock()
        mock_email.id = uuid.uuid4()
        mock_email.message_id = "<html-test@local>"
        mock_email.from_address = "alert@security.local"
        mock_email.from_domain = "security.local"
        mock_email.to_addresses = ["admin@security.local"]
        mock_email.cc_addresses = []
        mock_email.reply_to = None
        mock_email.subject = "System Notification"
        mock_email.received_at = now
        mock_email.has_attachments = False
        mock_email.attachment_count = 0
        mock_email.header = None
        mock_email.attachments = []
        mock_email.urls = []

        mock_risk_score = MagicMock()
        mock_risk_score.overall_risk_score = 10
        mock_risk_score.composite_score = 10
        mock_risk_score.scoring_version = "1.0"
        mock_risk_score.spf_subscore = 0.0
        mock_risk_score.dkim_subscore = 0.0
        mock_risk_score.dmarc_subscore = 0.0
        mock_risk_score.ml_subscore = 0.0
        mock_risk_score.url_subscore = 0.0
        mock_risk_score.attachment_subscore = 0.0
        mock_risk_score.sender_reputation_subscore = 0.0
        mock_risk_score.factor_breakdown = []

        mock_analysis = MagicMock()
        mock_analysis.id = analysis_id
        mock_analysis.org_id = org_id
        mock_analysis.email = mock_email
        mock_analysis.risk_score = mock_risk_score
        mock_analysis.ml_prediction = None
        mock_analysis.llm_analysis = None
        mock_analysis.threat_signals = []
        mock_analysis.threat_intel_results = []
        mock_analysis.overall_risk_score = 10
        from app.infrastructure.db.models.enums import AnalysisStatus, AnalysisVerdict, RiskLevel
        mock_analysis.risk_level = RiskLevel.SAFE
        mock_analysis.verdict = AnalysisVerdict.CLEAN
        mock_analysis.status = AnalysisStatus.COMPLETE
        mock_analysis.started_at = now
        mock_analysis.completed_at = now
        mock_analysis.duration_ms = 500

        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None
        mock_analyses_repo = AsyncMock()
        mock_analyses_repo.get_with_full_details.return_value = mock_analysis
        mock_uow.analyses = mock_analyses_repo

        mock_audit_repo = AsyncMock()
        mock_uow.audit_logs = mock_audit_repo
        mock_uow.commit = AsyncMock()

        mock_session = AsyncMock()
        mock_exec_res = MagicMock()
        mock_exec_res.scalar_one_or_none.return_value = "Demo Security Tenant"
        mock_session.execute.return_value = mock_exec_res
        mock_uow.session = mock_session

        mock_users_repo = AsyncMock()
        mock_users_repo.get_by_id.return_value = None
        mock_uow.users = mock_users_repo

        caller_claims = TokenClaims(
            user_id=uuid.uuid4(),
            role="user",
            org_id=org_id,
            jti=uuid.uuid4(),
            token_type="access",
            exp=datetime.now(UTC),
        )

        from app.api.dependencies import get_optional_user_claims

        app.dependency_overrides[get_uow] = lambda: mock_uow
        app.dependency_overrides[get_optional_user_claims] = lambda: caller_claims

        try:
            response = await async_client.get(
                f"/api/v1/reports/analysis/{analysis_id}?format=html"
            )
            assert response.status_code == 200
            assert "text/html" in response.headers.get("content-type", "")
            assert "<!DOCTYPE html>" in response.text
            assert "Email Security Incident Report" in response.text
            assert "Verdict: CLEAN" in response.text
            assert mock_audit_repo.create.called
            audit_call_arg = mock_audit_repo.create.call_args[0][0]
            assert audit_call_arg.metadata_payload["format"] == "html"
        finally:
            app.dependency_overrides.pop(get_uow, None)
            app.dependency_overrides.pop(get_optional_user_claims, None)
