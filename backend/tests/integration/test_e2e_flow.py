"""Complete End-to-End integration flow tests.

Covers the user lifecycle:
1. User authentication / login
2. Email submission (asynchronous pipeline ingestion)
3. Pipeline analysis processing
4. Detailed threat forensics retrieval
5. Analysis History searching & pagination
6. Dashboard metrics & chart updates
7. Security report generation & audit trail
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.dependencies import get_current_user_claims, get_optional_user_claims, get_uow
from app.api.schemas.history import AnalysisHistoryItem
from app.infrastructure.db.models.analysis import (
    Analysis,
    LLMAnalysis,
    RiskScore,
    ThreatIntelligenceResult,
    ThreatSignal,
)
from app.infrastructure.db.models.email import Email
from app.infrastructure.db.models.enums import (
    AnalysisStatus,
    AnalysisVerdict,
    AttackType,
    RiskLevel,
    ThreatCategory,
    ThreatSeverity,
    UserRoleType,
)
from app.infrastructure.db.models.organization import Organization
from app.main import app
from app.services.token_service import TokenClaims



@pytest.mark.asyncio
async def test_complete_end_to_end_analysis_workflow() -> None:
    """Execute complete end-to-end user journey across all API modules."""
    test_org_id = uuid.uuid4()
    test_user_id = uuid.uuid4()
    test_analysis_id = uuid.uuid4()
    test_email_id = uuid.uuid4()

    # Step 1: Prepare authenticated claims
    claims = TokenClaims(
        user_id=test_user_id,
        role=UserRoleType.SECURITY_ANALYST.value,
        org_id=test_org_id,
        jti=uuid.uuid4(),
        token_type="access",
        exp=datetime.now(UTC),
    )


    # Step 2: Build mock records for the completed pipeline
    mock_email = MagicMock(spec=Email)
    mock_email.id = test_email_id
    mock_email.org_id = test_org_id
    mock_email.from_address = "security-alert@micros0ft-security.com"
    mock_email.from_domain = "micros0ft-security.com"
    mock_email.subject = "Action Required: Immediate Account Verification"
    mock_email.received_at = datetime.now(UTC)
    mock_email.body_plain = "Please verify your credentials at http://micros0ft-security.com/login"
    mock_email.body_preview = "Please verify your credentials..."
    mock_email.header = None
    mock_email.urls = []
    mock_email.attachments = []
    # Fields accessed by ReportService.build_report — must be str | None, not MagicMock
    mock_email.message_id = None
    mock_email.reply_to = None
    mock_email.return_path = None
    mock_email.to_addresses = ["victim@corp.com"]
    mock_email.cc_addresses = []
    mock_email.has_attachments = False
    mock_email.attachment_count = 0

    mock_analysis = MagicMock(spec=Analysis)
    mock_analysis.id = test_analysis_id
    mock_analysis.email_id = test_email_id
    mock_analysis.org_id = test_org_id
    mock_analysis.status = AnalysisStatus.COMPLETE
    mock_analysis.verdict = AnalysisVerdict.MALICIOUS
    mock_analysis.overall_risk_score = 92
    mock_analysis.risk_level = RiskLevel.CRITICAL
    mock_analysis.started_at = datetime.now(UTC)
    mock_analysis.completed_at = datetime.now(UTC)
    mock_analysis.duration_ms = 1240
    mock_analysis.error_message = None
    mock_analysis.events = []

    # Risk score
    mock_risk = MagicMock(spec=RiskScore)
    mock_risk.composite_score = 92
    mock_risk.risk_level = RiskLevel.CRITICAL
    mock_risk.spf_subscore = 100.0
    mock_risk.ml_subscore = 95.0
    mock_risk.sender_reputation_subscore = 80.0
    mock_risk.factor_breakdown = {"spf": "fail", "dkim": "none"}
    mock_risk.scoring_version = "2026.1"
    mock_analysis.risk_score = mock_risk

    # Threat signals
    mock_sig = MagicMock(spec=ThreatSignal)
    mock_sig.id = uuid.uuid4()
    mock_sig.signal_type = "domain_impersonation"
    mock_sig.category = ThreatCategory.BRAND_IMPERSONATION
    mock_sig.severity = ThreatSeverity.CRITICAL
    mock_sig.attack_type = AttackType.SPEAR_PHISHING
    mock_sig.confidence = 0.95
    mock_sig.source_engine = "heuristic_analyzer"
    mock_sig.title = "Brand Impersonation Detected"
    mock_sig.description = "Sender domain typosquats Microsoft brand."
    mock_sig.indicator_value = "micros0ft-security.com"
    mock_analysis.threat_signals = [mock_sig]

    # LLM analysis
    mock_llm = MagicMock(spec=LLMAnalysis)
    mock_llm.model_name = "llama-3.3-70b-versatile"
    mock_llm.prompt_version = "2026.1"
    mock_llm.threat_narrative = "Urgent credential harvesting lure using brand impersonation."
    mock_llm.executive_summary = "High-risk credential harvesting campaign targeting user credentials."
    mock_llm.recommended_action = "quarantine"
    mock_llm.reasoning = "Combines fake domain with artificial urgency."
    mock_llm.extracted_iocs = [{"type": "domain", "value": "micros0ft-security.com"}]
    mock_llm.safety_passed = True
    mock_llm.confidence_score = 0.95
    mock_llm.latency_ms = 450
    mock_analysis.llm_analysis = mock_llm
    mock_analysis.ml_prediction = None
    mock_analysis.threat_intel_results = []
    mock_analysis.email = mock_email

    # Step 3: Wire UOW mocks
    mock_uow = MagicMock()
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.flush = AsyncMock()
    mock_uow.__aenter__.return_value = mock_uow
    mock_uow.__aexit__.return_value = None
    mock_uow.session = mock_session
    mock_uow.commit = AsyncMock()

    mock_org = MagicMock(spec=Organization)
    mock_org.id = test_org_id
    mock_org.name = "Enterprise Security Corp"
    mock_exec_result = MagicMock()
    # When select(Organization.name) or select(Organization) is called, return string or org
    mock_exec_result.scalar_one_or_none.return_value = "Enterprise Security Corp"
    mock_session.execute = AsyncMock(return_value=mock_exec_result)

    mock_uow.analyses.get_with_full_details = AsyncMock(return_value=mock_analysis)
    mock_uow.analyses.get_by_id = AsyncMock(return_value=mock_analysis)

    # Users mock — required by _resolve_tenant_and_user in reports.py
    mock_user = MagicMock()
    mock_user.id = test_user_id
    mock_user.email = "analyst@corp.com"
    mock_uow.users = MagicMock()
    mock_uow.users.get_by_id = AsyncMock(return_value=mock_user)

    # History mock
    mock_history_item = {
        "analysis_id": str(test_analysis_id),
        "email_id": str(test_email_id),
        "timestamp": datetime.now(UTC),
        "sender": "security-alert@micros0ft-security.com",
        "sender_domain": "micros0ft-security.com",
        "subject": "Action Required: Immediate Account Verification",
        "classification": "malicious",
        "severity": "critical",
        "risk_score": 92,
        "status": "completed",
        "attack_type": "spear_phishing",
        "duration_ms": 1240,
    }
    mock_uow.analyses.get_paginated_history = AsyncMock(
        return_value=([mock_history_item], 1)
    )


    # Dashboard mock
    mock_metrics = {
        "total_emails_analyzed": 1,
        "threats_detected": 1,
        "high_risk_emails": 0,
        "critical_threats": 1,
        "phishing_count": 1,
        "bec_count": 0,
        "credential_theft_count": 1,
        "malware_count": 0,
        "average_risk_score": 92.0,
        "analysis_success_rate": 100.0,
        "llm_utilization_rate": 100.0,
        "average_latency_ms": 1240.0,
    }
    mock_uow.dashboard.get_metrics = AsyncMock(return_value=mock_metrics)
    mock_uow.dashboard.get_charts = AsyncMock(return_value={})
    mock_uow.dashboard.get_recent_threats = AsyncMock(return_value=[])

    # Audit log mock — required by report generation
    mock_uow.audit_logs = MagicMock()
    mock_uow.audit_logs.create = AsyncMock(return_value=None)

    app.dependency_overrides[get_uow] = lambda: mock_uow
    app.dependency_overrides[get_optional_user_claims] = lambda: claims
    app.dependency_overrides[get_current_user_claims] = lambda: claims

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # 1. Submit email for analysis
            with patch("app.api.routers.analysis.submit_analysis_job", new_callable=AsyncMock) as mock_submit:
                submit_resp = await client.post(
                    "/api/v1/analysis",
                    json={
                        "from_address": "security-alert@micros0ft-security.com",
                        "to_addresses": ["victim@corp.com"],
                        "subject": "Action Required: Immediate Account Verification",
                        "body_plain": "Please verify your credentials at http://micros0ft-security.com/login",
                    },
                )
                assert submit_resp.status_code == 202
                submit_data = submit_resp.json()
                assert submit_data["status"] == "queued"
                assert "analysis_id" in submit_data
                mock_submit.assert_awaited_once()

            # 2. Worker health telemetry
            health_resp = await client.get("/api/v1/analysis/worker/health")
            assert health_resp.status_code == 200

            # 3. Retrieve analysis details and forensics
            detail_resp = await client.get(f"/api/v1/analysis/{test_analysis_id}")
            assert detail_resp.status_code == 200
            detail = detail_resp.json()
            assert detail["overall_risk_score"] == 92
            assert detail["risk_level"] == "critical"
            assert detail["verdict"] == "malicious"
            assert len(detail["threat_signals"]) == 1
            assert detail["threat_signals"][0]["signal_type"] == "domain_impersonation"
            assert detail["llm_analysis"]["recommended_action"] == "quarantine"

            # 4. Analysis History search
            history_resp = await client.get("/api/v1/analysis/history?page=1&page_size=20")
            assert history_resp.status_code == 200
            hist = history_resp.json()
            assert hist["total_count"] == 1
            assert hist["items"][0]["risk_score"] == 92
            assert hist["items"][0]["classification"] == "malicious"


            # 5. Dashboard metrics reflects latest stats
            dash_resp = await client.get("/api/v1/dashboard/metrics")
            assert dash_resp.status_code == 200
            dash = dash_resp.json()
            assert dash["total_emails_analyzed"] == 1
            assert dash["critical_threats"] == 1
            assert dash["average_risk_score"] == 92.0

            # 6. Generate JSON Report
            report_resp = await client.get(f"/api/v1/reports/analysis/{test_analysis_id}?format=json")
            assert report_resp.status_code == 200
            report = report_resp.json()
            # AnalysisReportResponse nests verdict in classification and risk_score
            assert report["classification"]["verdict"] == "malicious"
            assert report["risk_score"]["overall_risk_score"] == 92
            assert len(report["security_signals"]) == 1

            # 7. Generate HTML Printable Report
            html_report_resp = await client.get(f"/api/v1/reports/analysis/{test_analysis_id}?format=html")
            assert html_report_resp.status_code == 200
            assert "text/html" in html_report_resp.headers["content-type"]
            assert "@media print" in html_report_resp.text
            assert "Action Required: Immediate Account Verification" in html_report_resp.text

    finally:
        app.dependency_overrides.pop(get_uow, None)
        app.dependency_overrides.pop(get_optional_user_claims, None)
        app.dependency_overrides.pop(get_current_user_claims, None)
