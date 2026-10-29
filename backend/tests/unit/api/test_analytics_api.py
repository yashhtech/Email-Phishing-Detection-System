"""Unit tests for the Security Analytics API, schemas, and repository."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient

from app.api.dependencies import get_uow
from app.api.schemas.analytics import (
    AnalyticsOverviewResponse,
    AttackTypeTrendPoint,
    DateRangeMeta,
    DetectionRatePoint,
    FalsePositiveStats,
    LLMUtilizationMetrics,
    MLPerformanceMetrics,
    ProcessingLatencyStats,
    RiskDistributionPoint,
    SenderDomainPoint,
    ThreatIntelUsageStats,
    ThreatTrendPoint,
)
from app.infrastructure.db.repositories.analytics_repo import AnalyticsRepository
from app.main import app

# ===========================================================================
# 1. Analytics Schema Validation Tests
# ===========================================================================


class TestAnalyticsSchemas:
    """Validate Pydantic models and serialization contracts for Analytics schemas."""

    def test_date_range_meta_serialization(self) -> None:
        now = datetime.now(UTC)
        meta = DateRangeMeta(start=now - timedelta(days=7), end=now, preset="7d", use_hourly=False)
        data = meta.model_dump(mode="json")
        assert data["preset"] == "7d"
        assert data["use_hourly"] is False
        assert "start" in data
        assert "end" in data

    def test_overview_response_defaults_are_zero_safe(self) -> None:
        now = datetime.now(UTC)
        meta = DateRangeMeta(start=now - timedelta(days=7), end=now, preset="7d")
        overview = AnalyticsOverviewResponse(date_range=meta)

        assert overview.threat_trends == []
        assert overview.attack_type_trends == []
        assert overview.risk_distribution == []
        assert overview.sender_domains == []
        assert overview.detection_rate == []
        assert overview.false_positive_stats.reported_count == 0
        assert overview.false_positive_stats.confirmed_false_positive == 0
        assert overview.false_positive_stats.false_positive_rate == 0.0
        assert overview.ml_performance.total_predictions == 0
        assert overview.ml_performance.avg_confidence == 0.0
        assert overview.llm_utilization.total_calls == 0
        assert overview.processing_latency.p50_ms == 0.0
        assert overview.threat_intel_usage.total_queries == 0

    def test_all_schema_points_instantiation(self) -> None:
        now = datetime.now(UTC)
        tt = ThreatTrendPoint(
            timestamp=now,
            total=10,
            clean=5,
            suspicious=2,
            malicious=3,
            quarantine=1,
            block=2,
        )
        assert tt.total == 10
        assert tt.clean == 5

        at = AttackTypeTrendPoint(attack_type="spear_phishing", count=15, percentage=42.5)
        assert at.attack_type == "spear_phishing"
        assert at.percentage == 42.5

        rd = RiskDistributionPoint(tier="critical", count=8, percentage=20.0)
        assert rd.tier == "critical"
        assert rd.count == 8

        sd = SenderDomainPoint(
            domain="evil-phish.com",
            total_emails=25,
            threat_count=20,
            threat_rate=80.0,
            clean_count=5,
        )
        assert sd.domain == "evil-phish.com"
        assert sd.threat_rate == 80.0

        dr = DetectionRatePoint(
            timestamp=now,
            total_analyzed=100,
            threats_detected=15,
            detection_rate=15.0,
        )
        assert dr.detection_rate == 15.0

        fp = FalsePositiveStats(
            reported_count=4, confirmed_false_positive=2, false_positive_rate=5.0
        )
        assert fp.confirmed_false_positive == 2

        ml = MLPerformanceMetrics(
            total_predictions=120,
            avg_confidence=0.925,
            avg_latency_ms=18.4,
            phishing_detected=30,
            clean_detected=80,
            spam_detected=10,
            malware_detected=0,
        )
        assert ml.total_predictions == 120
        assert ml.avg_confidence == 0.925

        llm = LLMUtilizationMetrics(
            total_calls=45,
            avg_confidence=0.88,
            avg_latency_ms=640.2,
            total_prompt_tokens=15000,
            total_completion_tokens=4200,
            total_tokens=19200,
            safety_pass_rate=97.8,
            models_breakdown={"llama-3.3-70b-versatile": 45},
        )
        assert llm.total_tokens == 19200
        assert llm.safety_pass_rate == 97.8

        lat = ProcessingLatencyStats(
            p50_ms=450.0,
            p90_ms=1100.0,
            p95_ms=1350.0,
            p99_ms=1800.0,
            avg_ms=520.0,
            min_ms=120.0,
            max_ms=2100.0,
        )
        assert lat.p95_ms == 1350.0

        ti = ThreatIntelUsageStats(
            total_queries=200,
            malicious_hits=35,
            suspicious_hits=15,
            clean_hits=140,
            unknown_hits=10,
            providers_breakdown={"virustotal": 150, "whois": 50},
        )
        assert ti.total_queries == 200
        assert ti.providers_breakdown["virustotal"] == 150


# ===========================================================================
# 2. Date Range Resolution Logic Tests
# ===========================================================================


class TestDateRangeResolution:
    """Validate AnalyticsRepository._resolve_time_range calculation logic."""

    def test_resolve_preset_24h(self) -> None:
        start, end, preset, use_hourly = AnalyticsRepository._resolve_time_range(preset="24h")
        assert preset == "24h"
        assert use_hourly is True
        delta = end - start
        assert abs(delta.total_seconds() - 86400) < 5

    def test_resolve_preset_7d(self) -> None:
        start, end, preset, use_hourly = AnalyticsRepository._resolve_time_range(preset="7d")
        assert preset == "7d"
        assert use_hourly is False
        delta = end - start
        assert abs(delta.total_seconds() - (7 * 86400)) < 5

    def test_resolve_preset_30d(self) -> None:
        start, end, preset, use_hourly = AnalyticsRepository._resolve_time_range(preset="30d")
        assert preset == "30d"
        assert use_hourly is False
        delta = end - start
        assert abs(delta.total_seconds() - (30 * 86400)) < 5

    def test_resolve_preset_90d(self) -> None:
        start, end, preset, use_hourly = AnalyticsRepository._resolve_time_range(preset="90d")
        assert preset == "90d"
        assert use_hourly is False
        delta = end - start
        assert abs(delta.total_seconds() - (90 * 86400)) < 5

    def test_resolve_custom_range_hourly(self) -> None:
        now = datetime.now(UTC)
        start = now - timedelta(hours=12)
        resolved_start, resolved_end, _preset, use_hourly = (
            AnalyticsRepository._resolve_time_range(start=start, end=now)
        )
        assert use_hourly is True
        assert resolved_start == start
        assert resolved_end == now

    def test_resolve_custom_range_daily(self) -> None:
        now = datetime.now(UTC)
        start = now - timedelta(days=14)
        resolved_start, resolved_end, _preset, use_hourly = (
            AnalyticsRepository._resolve_time_range(start=start, end=now)
        )
        assert use_hourly is False
        assert resolved_start == start
        assert resolved_end == now

    def test_resolve_default_when_empty(self) -> None:
        _start, _end, preset, use_hourly = AnalyticsRepository._resolve_time_range()
        assert preset == "7d"
        assert use_hourly is False


# ===========================================================================
# 3. Analytics API Router Endpoints Tests
# ===========================================================================


@pytest.mark.asyncio
class TestAnalyticsAPI:
    """Validate HTTP endpoints for Analytics overview and CSV export."""

    async def test_get_analytics_overview_success(self, async_client: AsyncClient) -> None:
        now = datetime.now(UTC)
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None

        mock_analytics_repo = AsyncMock()
        mock_analytics_repo.get_overview.return_value = AnalyticsOverviewResponse(
            date_range=DateRangeMeta(
                start=now - timedelta(days=7),
                end=now,
                preset="7d",
                use_hourly=False,
            ),
            threat_trends=[
                ThreatTrendPoint(
                    timestamp=now - timedelta(days=1),
                    total=50,
                    clean=35,
                    suspicious=10,
                    malicious=5,
                    quarantine=2,
                    block=3,
                )
            ],
            attack_type_trends=[
                AttackTypeTrendPoint(attack_type="spear_phishing", count=8, percentage=53.3)
            ],
            risk_distribution=[RiskDistributionPoint(tier="critical", count=5, percentage=10.0)],
            sender_domains=[
                SenderDomainPoint(
                    domain="phishing-attacker.com",
                    total_emails=20,
                    threat_count=18,
                    threat_rate=90.0,
                    clean_count=2,
                )
            ],
            detection_rate=[
                DetectionRatePoint(
                    timestamp=now - timedelta(days=1),
                    total_analyzed=50,
                    threats_detected=15,
                    detection_rate=30.0,
                )
            ],
            false_positive_stats=FalsePositiveStats(
                reported_count=2,
                confirmed_false_positive=1,
                false_positive_rate=6.7,
            ),
            ml_performance=MLPerformanceMetrics(
                total_predictions=50,
                avg_confidence=0.91,
                avg_latency_ms=22.5,
                phishing_detected=15,
                clean_detected=35,
                spam_detected=0,
                malware_detected=0,
            ),
            llm_utilization=LLMUtilizationMetrics(
                total_calls=25,
                avg_confidence=0.86,
                avg_latency_ms=720.0,
                total_prompt_tokens=8000,
                total_completion_tokens=2500,
                total_tokens=10500,
                safety_pass_rate=100.0,
                models_breakdown={"llama-3.3-70b-versatile": 25},
            ),
            processing_latency=ProcessingLatencyStats(
                p50_ms=480.0,
                p90_ms=1050.0,
                p95_ms=1280.0,
                p99_ms=1750.0,
                avg_ms=530.0,
                min_ms=110.0,
                max_ms=1900.0,
            ),
            threat_intel_usage=ThreatIntelUsageStats(
                total_queries=60,
                malicious_hits=12,
                suspicious_hits=8,
                clean_hits=38,
                unknown_hits=2,
                providers_breakdown={"virustotal": 60},
            ),
        )
        mock_uow.analytics = mock_analytics_repo

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            res = await async_client.get("/api/v1/analytics/overview?preset=7d")
            assert res.status_code == 200
            data = res.json()
            assert data["date_range"]["preset"] == "7d"
            assert len(data["threat_trends"]) == 1
            assert data["threat_trends"][0]["total"] == 50
            assert len(data["attack_type_trends"]) == 1
            assert data["attack_type_trends"][0]["attack_type"] == "spear_phishing"
            assert data["false_positive_stats"]["confirmed_false_positive"] == 1
            assert data["ml_performance"]["total_predictions"] == 50
            assert data["llm_utilization"]["total_tokens"] == 10500
            assert data["processing_latency"]["p95_ms"] == 1280.0
            assert data["threat_intel_usage"]["malicious_hits"] == 12
        finally:
            app.dependency_overrides.pop(get_uow, None)

    async def test_get_analytics_overview_invalid_preset_returns_400(
        self, async_client: AsyncClient
    ) -> None:
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None
        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            res = await async_client.get("/api/v1/analytics/overview?preset=invalid_preset")
            assert res.status_code == 400
            assert "Invalid preset" in res.json()["detail"]
        finally:
            app.dependency_overrides.pop(get_uow, None)

    async def test_get_analytics_overview_invalid_date_order_returns_400(
        self, async_client: AsyncClient
    ) -> None:
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None
        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            res = await async_client.get(
                "/api/v1/analytics/overview?start=2026-09-30T10:00:00Z&end=2026-09-29T10:00:00Z"
            )
            assert res.status_code == 400
            assert "Start date must be earlier" in res.json()["detail"]
        finally:
            app.dependency_overrides.pop(get_uow, None)

    async def test_export_analytics_csv_streaming_success(self, async_client: AsyncClient) -> None:
        now = datetime.now(UTC)
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None

        mock_analytics_repo = AsyncMock()
        mock_analytics_repo.get_overview.return_value = AnalyticsOverviewResponse(
            date_range=DateRangeMeta(start=now - timedelta(days=7), end=now, preset="7d"),
            threat_trends=[
                ThreatTrendPoint(
                    timestamp=now,
                    total=10,
                    clean=6,
                    suspicious=2,
                    malicious=2,
                    quarantine=0,
                    block=1,
                )
            ],
            attack_type_trends=[
                AttackTypeTrendPoint(attack_type="credential_harvesting", count=5, percentage=50.0)
            ],
            risk_distribution=[RiskDistributionPoint(tier="high", count=4, percentage=40.0)],
            sender_domains=[
                SenderDomainPoint(
                    domain="spoofed-domain.com",
                    total_emails=10,
                    threat_count=8,
                    threat_rate=80.0,
                    clean_count=2,
                )
            ],
        )
        mock_uow.analytics = mock_analytics_repo

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            res = await async_client.get("/api/v1/analytics/export?preset=7d")
            assert res.status_code == 200
            assert res.headers["content-type"].startswith("text/csv")
            assert "Content-Disposition" in res.headers
            assert "attachment; filename=" in res.headers["Content-Disposition"]

            csv_content = res.text
            assert "# SECTION: THREAT TRENDS" in csv_content
            assert "Clean" in csv_content
            assert "# SECTION: ATTACK TYPES" in csv_content
            assert "credential_harvesting" in csv_content
            assert "# SECTION: RISK DISTRIBUTION" in csv_content
            assert "high" in csv_content
            assert "# SECTION: SENDER DOMAINS" in csv_content
            assert "spoofed-domain.com" in csv_content
        finally:
            app.dependency_overrides.pop(get_uow, None)

    async def test_export_analytics_csv_invalid_preset_returns_400(
        self, async_client: AsyncClient
    ) -> None:
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None
        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            res = await async_client.get("/api/v1/analytics/export?preset=unknown")
            assert res.status_code == 400
            assert "Invalid preset" in res.json()["detail"]
        finally:
            app.dependency_overrides.pop(get_uow, None)


# ===========================================================================
# 4. Analytics Repository Logic Tests with Mocked Sessions
# ===========================================================================


@pytest.mark.asyncio
class TestAnalyticsRepository:
    """Validate AnalyticsRepository genuine aggregation queries with mocked async DB sessions."""

    async def test_get_overview_empty_database_returns_safe_zeroes(self) -> None:
        mock_session = AsyncMock()

        # 1. _threat_trends
        mock_threats_res = MagicMock()
        mock_threats_res.all.return_value = []

        # 2. _attack_type_trends
        mock_att_res = MagicMock()
        mock_att_res.all.return_value = []

        # 3. _risk_distribution
        mock_risk_res = MagicMock()
        mock_risk_res.all.return_value = []

        # 4. _sender_domain_trends
        mock_domain_res = MagicMock()
        mock_domain_res.all.return_value = []

        # 5. _detection_rate
        mock_det_res = MagicMock()
        mock_det_res.all.return_value = []

        # 6. _false_positive_stats
        mock_fp_res = MagicMock()
        mock_fp_res.first.return_value = MagicMock(reported_count=0, specific_fp_count=0)
        mock_fp_threat_res = MagicMock()
        mock_fp_threat_res.scalar_one_or_none.return_value = 0

        # 7. _ml_performance
        mock_ml_res = MagicMock()
        mock_ml_res.first.return_value = MagicMock(
            total=0,
            avg_confidence=None,
            avg_latency=None,
            phishing=0,
            clean=0,
            spam=0,
            malware=0,
        )

        # 8. _llm_utilization
        mock_llm_res = MagicMock()
        mock_llm_res.first.return_value = MagicMock(
            total_calls=0,
            avg_confidence=None,
            avg_latency=None,
            safety_passed_count=0,
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
        )
        mock_llm_models_res = MagicMock()
        mock_llm_models_res.all.return_value = []

        # 9. _processing_latency: row count check returns 0
        mock_lat_count_res = MagicMock()
        mock_lat_count_res.scalar_one_or_none.return_value = 0

        # 10. _threat_intel_usage
        mock_ti_res = MagicMock()
        mock_ti_res.first.return_value = MagicMock(
            total_queries=0,
            malicious_hits=0,
            suspicious_hits=0,
            clean_hits=0,
            unknown_hits=0,
        )
        mock_ti_providers_res = MagicMock()
        mock_ti_providers_res.all.return_value = []

        mock_session.execute.side_effect = [
            mock_threats_res,
            mock_att_res,
            mock_risk_res,
            mock_domain_res,
            mock_det_res,
            mock_fp_res,
            mock_fp_threat_res,
            mock_ml_res,
            mock_llm_res,
            mock_llm_models_res,
            mock_lat_count_res,
            mock_ti_res,
            mock_ti_providers_res,
        ]

        repo = AnalyticsRepository(mock_session)
        overview = await repo.get_overview(preset="7d")

        assert overview.date_range.preset == "7d"
        assert overview.threat_trends == []
        assert overview.attack_type_trends == []
        assert overview.risk_distribution == []
        assert overview.sender_domains == []
        assert overview.detection_rate == []
        assert overview.false_positive_stats.reported_count == 0
        assert overview.ml_performance.total_predictions == 0
        assert overview.llm_utilization.total_calls == 0
        assert overview.processing_latency.p50_ms == 0.0
        assert overview.threat_intel_usage.total_queries == 0
