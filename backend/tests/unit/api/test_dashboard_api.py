"""Unit tests for the production Security Dashboard API and Repository."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient

from app.api.dependencies import get_uow
from app.api.schemas.dashboard import (
    DashboardChartsResponse,
    DashboardMetricsResponse,
    LLMUsageMetric,
    RecentThreatItem,
)
from app.infrastructure.db.repositories.dashboard_repo import DashboardRepository
from app.main import app

# ===========================================================================
# 1. Dashboard Schema Validation Tests
# ===========================================================================


class TestDashboardSchemas:
    """Validate Pydantic models for Dashboard API contracts."""

    def test_metrics_response_defaults_are_zero_safe(self) -> None:
        metrics = DashboardMetricsResponse()
        assert metrics.total_emails_analyzed == 0
        assert metrics.threats_detected == 0
        assert metrics.high_risk_emails == 0
        assert metrics.critical_threats == 0
        assert metrics.phishing_count == 0
        assert metrics.bec_count == 0
        assert metrics.credential_theft_count == 0
        assert metrics.malware_related_events == 0
        assert metrics.average_risk_score == 0.0
        assert metrics.analysis_success_rate == 100.0
        assert metrics.average_analysis_latency_ms == 0.0
        assert metrics.llm_usage.total_calls == 0

    def test_charts_response_defaults_are_empty_lists(self) -> None:
        charts = DashboardChartsResponse()
        assert isinstance(charts.threats_over_time, list)
        assert isinstance(charts.risk_distribution, list)
        assert isinstance(charts.attack_type_distribution, list)
        assert isinstance(charts.severity_distribution, list)
        assert isinstance(charts.processing_time_distribution, list)
        assert isinstance(charts.detection_trends, list)
        assert isinstance(charts.recent_threats, list)
        assert isinstance(charts.llm_usage, LLMUsageMetric)


# ===========================================================================
# 2. Dashboard API Router Tests
# ===========================================================================


class TestDashboardAPI:
    """Validate HTTP endpoints for Dashboard."""

    @pytest.mark.asyncio
    async def test_get_dashboard_metrics_success(self, async_client: AsyncClient) -> None:
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None

        mock_dashboard_repo = AsyncMock()
        mock_dashboard_repo.get_metrics.return_value = DashboardMetricsResponse(
            total_emails_analyzed=150,
            threats_detected=42,
            high_risk_emails=18,
            critical_threats=7,
            phishing_count=24,
            bec_count=9,
            credential_theft_count=12,
            malware_related_events=5,
            average_risk_score=38.4,
            analysis_success_rate=98.7,
            average_analysis_latency_ms=1240.5,
            llm_usage=LLMUsageMetric(
                total_calls=150,
                analyzed_calls=42,
                skipped_calls=108,
                average_latency_ms=620.0,
                models_breakdown={"llama-3.3-70b-versatile": 42},
            ),
        )
        mock_uow.dashboard = mock_dashboard_repo

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            response = await async_client.get("/api/v1/dashboard/metrics")
            assert response.status_code == 200
            data = response.json()

            assert data["total_emails_analyzed"] == 150
            assert data["threats_detected"] == 42
            assert data["high_risk_emails"] == 18
            assert data["critical_threats"] == 7
            assert data["phishing_count"] == 24
            assert data["bec_count"] == 9
            assert data["credential_theft_count"] == 12
            assert data["malware_related_events"] == 5
            assert data["average_risk_score"] == 38.4
            assert data["analysis_success_rate"] == 98.7
            assert data["average_analysis_latency_ms"] == 1240.5
            assert data["llm_usage"]["total_calls"] == 150
            assert data["llm_usage"]["analyzed_calls"] == 42
        finally:
            app.dependency_overrides.pop(get_uow, None)

    @pytest.mark.asyncio
    async def test_get_dashboard_charts_success(self, async_client: AsyncClient) -> None:
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None

        mock_dashboard_repo = AsyncMock()
        mock_dashboard_repo.get_charts_data.return_value = DashboardChartsResponse(
            threats_over_time=[],
            risk_distribution=[],
            attack_type_distribution=[],
            severity_distribution=[],
            processing_time_distribution=[],
            detection_trends=[],
            recent_threats=[],
            llm_usage=LLMUsageMetric(),
        )
        mock_uow.dashboard = mock_dashboard_repo

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            response = await async_client.get("/api/v1/dashboard/charts?days=7")
            assert response.status_code == 200
            data = response.json()
            assert "threats_over_time" in data
            assert "risk_distribution" in data
            assert "attack_type_distribution" in data
            assert "severity_distribution" in data
            assert "processing_time_distribution" in data
            assert "llm_usage" in data
            assert "detection_trends" in data
            assert "recent_threats" in data
        finally:
            app.dependency_overrides.pop(get_uow, None)

    @pytest.mark.asyncio
    async def test_get_recent_threats_success(self, async_client: AsyncClient) -> None:
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None

        mock_dashboard_repo = AsyncMock()
        mock_dashboard_repo.get_recent_threats.return_value = [
            RecentThreatItem(
                analysis_id=str(uuid.uuid4()),
                email_id=str(uuid.uuid4()),
                subject="URGENT: Payroll Verification",
                from_address="hr@payrol-portal.com",
                from_domain="payrol-portal.com",
                risk_score=92,
                risk_level="critical",
                verdict="malicious",
                attack_type="Spear Phishing",
                category="Credential Theft",
                received_at="2026-09-29T12:00:00Z",
                has_attachments=False,
            )
        ]
        mock_uow.dashboard = mock_dashboard_repo

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            response = await async_client.get("/api/v1/dashboard/recent-threats?limit=5")
            assert response.status_code == 200
            items = response.json()
            assert len(items) == 1
            assert items[0]["subject"] == "URGENT: Payroll Verification"
            assert items[0]["risk_score"] == 92
            assert items[0]["risk_level"] == "critical"
            assert items[0]["verdict"] == "malicious"
        finally:
            app.dependency_overrides.pop(get_uow, None)


# ===========================================================================
# 3. Dashboard Repository Calculation Logic Tests
# ===========================================================================


class TestDashboardRepository:
    """Validate calculation queries with mocked database sessions."""

    @pytest.mark.asyncio
    async def test_get_metrics_empty_database_returns_safe_zeroes(self) -> None:
        mock_session = AsyncMock()

        # Mock query results for empty database
        mock_total_res = MagicMock()
        mock_total_row = MagicMock(
            total=0,
            completed=0,
            failed=0,
            avg_risk=None,
            avg_latency=None,
            threats=0,
            high_risk=0,
            critical=0,
        )
        mock_total_res.first.return_value = mock_total_row

        mock_sig_res = MagicMock()
        mock_sig_row = MagicMock(phishing=0, bec=0, credentials=0, malware=0)
        mock_sig_res.first.return_value = mock_sig_row

        mock_att_res = MagicMock()
        mock_att_res.scalar_one_or_none.return_value = 0

        mock_llm_res = MagicMock()
        mock_llm_row = MagicMock(total_llm=0, avg_llm_latency=None)
        mock_llm_res.first.return_value = mock_llm_row

        mock_model_res = MagicMock()
        mock_model_res.all.return_value = []

        mock_session.execute.side_effect = [
            mock_total_res,
            mock_sig_res,
            mock_att_res,
            mock_llm_res,
            mock_model_res,
        ]

        repo = DashboardRepository(mock_session)
        metrics = await repo.get_metrics()

        assert metrics.total_emails_analyzed == 0
        assert metrics.threats_detected == 0
        assert metrics.high_risk_emails == 0
        assert metrics.critical_threats == 0
        assert metrics.phishing_count == 0
        assert metrics.bec_count == 0
        assert metrics.credential_theft_count == 0
        assert metrics.malware_related_events == 0
        assert metrics.average_risk_score == 0.0
        assert metrics.analysis_success_rate == 100.0
        assert metrics.average_analysis_latency_ms == 0.0
        assert metrics.llm_usage.total_calls == 0
        assert metrics.llm_usage.analyzed_calls == 0
        assert metrics.llm_usage.skipped_calls == 0
