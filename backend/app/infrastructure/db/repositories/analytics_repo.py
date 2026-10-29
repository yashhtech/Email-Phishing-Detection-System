"""Authoritative PostgreSQL aggregation repository for Security Analytics."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Integer, case, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

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
from app.infrastructure.db.models.analysis import (
    Analysis,
    LLMAnalysis,
    MLPrediction,
    ThreatIntelligenceResult,
    ThreatSignal,
)
from app.infrastructure.db.models.email import Email
from app.infrastructure.db.models.enums import (
    AnalysisVerdict,
    ReputationVerdict,
)


class AnalyticsRepository:
    """Computes all security analytics and operational telemetry via PostgreSQL queries."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @staticmethod
    def _resolve_time_range(
        start: datetime | None = None,
        end: datetime | None = None,
        preset: str | None = None,
    ) -> tuple[datetime, datetime, str | None, bool]:
        """Normalize start and end bounds and determine hourly aggregation mode."""
        now = datetime.now(UTC)

        if start is not None and end is not None:
            if start.tzinfo is None:
                start = start.replace(tzinfo=UTC)
            if end.tzinfo is None:
                end = end.replace(tzinfo=UTC)
            use_hourly = (end - start).total_seconds() <= 86400
            return start, end, preset, use_hourly

        if start is not None and end is None:
            if start.tzinfo is None:
                start = start.replace(tzinfo=UTC)
            end = now
            use_hourly = (end - start).total_seconds() <= 86400
            return start, end, preset, use_hourly

        if end is not None and start is None:
            if end.tzinfo is None:
                end = end.replace(tzinfo=UTC)
            start = end - timedelta(days=7)
            return start, end, preset, False

        # Presets: '24h', '7d', '30d', '90d'
        selected_preset = preset or "7d"
        match selected_preset:
            case "24h":
                return now - timedelta(hours=24), now, "24h", True
            case "7d":
                return now - timedelta(days=7), now, "7d", False
            case "30d":
                return now - timedelta(days=30), now, "30d", False
            case "90d":
                return now - timedelta(days=90), now, "90d", False
            case _:
                return now - timedelta(days=7), now, "7d", False

    async def get_overview(
        self,
        org_id: uuid.UUID | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        preset: str | None = None,
    ) -> AnalyticsOverviewResponse:
        """Fetch complete production analytics overview payload directly from PostgreSQL."""
        resolved_start, resolved_end, active_preset, use_hourly = self._resolve_time_range(
            start=start, end=end, preset=preset
        )

        date_range = DateRangeMeta(
            start=resolved_start,
            end=resolved_end,
            preset=active_preset,
            use_hourly=use_hourly,
        )

        threat_trends = await self._threat_trends(
            org_id=org_id,
            start=resolved_start,
            end=resolved_end,
            use_hourly=use_hourly,
        )
        attack_type_trends = await self._attack_type_trends(
            org_id=org_id,
            start=resolved_start,
            end=resolved_end,
        )
        risk_dist = await self._risk_distribution(
            org_id=org_id,
            start=resolved_start,
            end=resolved_end,
        )
        sender_domains = await self._sender_domain_trends(
            org_id=org_id,
            start=resolved_start,
            end=resolved_end,
        )
        detection_rate = await self._detection_rate(
            org_id=org_id,
            start=resolved_start,
            end=resolved_end,
            use_hourly=use_hourly,
        )
        false_positive = await self._false_positive_stats(
            org_id=org_id,
            start=resolved_start,
            end=resolved_end,
        )
        ml_perf = await self._ml_performance(
            org_id=org_id,
            start=resolved_start,
            end=resolved_end,
        )
        llm_util = await self._llm_utilization(
            org_id=org_id,
            start=resolved_start,
            end=resolved_end,
        )
        proc_latency = await self._processing_latency(
            org_id=org_id,
            start=resolved_start,
            end=resolved_end,
        )
        threat_intel = await self._threat_intel_usage(
            org_id=org_id,
            start=resolved_start,
            end=resolved_end,
        )

        return AnalyticsOverviewResponse(
            date_range=date_range,
            threat_trends=threat_trends,
            attack_type_trends=attack_type_trends,
            risk_distribution=risk_dist,
            sender_domains=sender_domains,
            detection_rate=detection_rate,
            false_positive_stats=false_positive,
            ml_performance=ml_perf,
            llm_utilization=llm_util,
            processing_latency=proc_latency,
            threat_intel_usage=threat_intel,
        )

    async def _threat_trends(
        self,
        org_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        use_hourly: bool,
    ) -> list[ThreatTrendPoint]:
        """Aggregate email analysis outcomes into date or hourly time buckets."""
        interval = "hour" if use_hourly else "day"
        time_bucket = func.date_trunc(interval, Analysis.created_at).label("time_bucket")

        filters: list[Any] = [
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= start,
            Analysis.created_at <= end,
        ]
        if org_id is not None:
            filters.append(Analysis.org_id == org_id)

        stmt = (
            select(
                time_bucket,
                func.count(Analysis.id).label("total"),
                func.count(case((Analysis.verdict == AnalysisVerdict.CLEAN, 1))).label("clean"),
                func.count(case((Analysis.verdict == AnalysisVerdict.SUSPICIOUS, 1))).label(
                    "suspicious"
                ),
                func.count(case((Analysis.verdict == AnalysisVerdict.MALICIOUS, 1))).label(
                    "malicious"
                ),
                func.count(case((Analysis.verdict == AnalysisVerdict.QUARANTINE, 1))).label(
                    "quarantine"
                ),
                func.count(case((Analysis.verdict == AnalysisVerdict.BLOCK, 1))).label("block"),
            )
            .where(*filters)
            .group_by(time_bucket)
            .order_by(time_bucket.asc())
        )
        res = await self.session.execute(stmt)
        points: list[ThreatTrendPoint] = []
        for row in res.all():
            points.append(
                ThreatTrendPoint(
                    timestamp=row.time_bucket,
                    total=row.total or 0,
                    clean=row.clean or 0,
                    suspicious=row.suspicious or 0,
                    malicious=row.malicious or 0,
                    quarantine=row.quarantine or 0,
                    block=row.block or 0,
                )
            )
        return points

    async def _attack_type_trends(
        self,
        org_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[AttackTypeTrendPoint]:
        """Calculate counts and relative percentages for detected attack methodology types."""
        filters: list[Any] = [
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= start,
            Analysis.created_at <= end,
        ]
        if org_id is not None:
            filters.append(Analysis.org_id == org_id)

        stmt = (
            select(
                ThreatSignal.attack_type,
                func.count(ThreatSignal.id).label("attack_count"),
            )
            .join(Analysis, ThreatSignal.analysis_id == Analysis.id)
            .where(*filters)
            .group_by(ThreatSignal.attack_type)
            .order_by(func.count(ThreatSignal.id).desc())
        )
        res = await self.session.execute(stmt)
        rows = res.all()
        total_signals = sum(r.attack_count for r in rows if r.attack_count)

        points: list[AttackTypeTrendPoint] = []
        for r in rows:
            count = r.attack_count or 0
            pct = round((count / total_signals * 100.0), 2) if total_signals > 0 else 0.0
            attack_type_val = (
                r.attack_type.value
                if hasattr(r.attack_type, "value")
                else (str(r.attack_type) if r.attack_type else "unknown")
            )
            points.append(
                AttackTypeTrendPoint(
                    attack_type=attack_type_val,
                    count=count,
                    percentage=pct,
                )
            )
        return points

    async def _risk_distribution(
        self,
        org_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[RiskDistributionPoint]:
        """Aggregate total analyses by categorical risk level tier."""
        filters: list[Any] = [
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= start,
            Analysis.created_at <= end,
        ]
        if org_id is not None:
            filters.append(Analysis.org_id == org_id)

        stmt = (
            select(
                Analysis.risk_level,
                func.count(Analysis.id).label("tier_count"),
            )
            .where(*filters)
            .group_by(Analysis.risk_level)
            .order_by(func.count(Analysis.id).desc())
        )
        res = await self.session.execute(stmt)
        rows = res.all()
        total = sum(r.tier_count for r in rows if r.tier_count)

        points: list[RiskDistributionPoint] = []
        for r in rows:
            count = r.tier_count or 0
            pct = round((count / total * 100.0), 2) if total > 0 else 0.0
            tier_val = (
                r.risk_level.value
                if hasattr(r.risk_level, "value")
                else (str(r.risk_level) if r.risk_level else "unknown")
            )
            points.append(
                RiskDistributionPoint(
                    tier=tier_val,
                    count=count,
                    percentage=pct,
                )
            )
        return points

    async def _sender_domain_trends(
        self,
        org_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[SenderDomainPoint]:
        """Query top sender domains by email volume and threat incidence rate."""
        filters: list[Any] = [
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= start,
            Analysis.created_at <= end,
        ]
        if org_id is not None:
            filters.append(Analysis.org_id == org_id)

        threat_case = case(
            (
                or_(
                    Analysis.verdict.in_(
                        [
                            AnalysisVerdict.MALICIOUS,
                            AnalysisVerdict.SUSPICIOUS,
                            AnalysisVerdict.QUARANTINE,
                            AnalysisVerdict.BLOCK,
                        ]
                    ),
                    Analysis.overall_risk_score >= 50,
                ),
                1,
            )
        )
        clean_case = case((Analysis.verdict == AnalysisVerdict.CLEAN, 1))

        stmt = (
            select(
                Email.from_domain,
                func.count(Analysis.id).label("total_emails"),
                func.count(threat_case).label("threat_count"),
                func.count(clean_case).label("clean_count"),
            )
            .join(Email, Analysis.email_id == Email.id)
            .where(*filters)
            .group_by(Email.from_domain)
            .order_by(func.count(threat_case).desc(), func.count(Analysis.id).desc())
            .limit(20)
        )
        res = await self.session.execute(stmt)
        points: list[SenderDomainPoint] = []
        for r in res.all():
            total = r.total_emails or 0
            threats = r.threat_count or 0
            clean = r.clean_count or 0
            rate = round((threats / total * 100.0), 2) if total > 0 else 0.0
            points.append(
                SenderDomainPoint(
                    domain=r.from_domain or "unknown",
                    total_emails=total,
                    threat_count=threats,
                    threat_rate=rate,
                    clean_count=clean,
                )
            )
        return points

    async def _detection_rate(
        self,
        org_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        use_hourly: bool,
    ) -> list[DetectionRatePoint]:
        """Track threat detection proportion over time buckets."""
        interval = "hour" if use_hourly else "day"
        time_bucket = func.date_trunc(interval, Analysis.created_at).label("time_bucket")

        filters: list[Any] = [
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= start,
            Analysis.created_at <= end,
        ]
        if org_id is not None:
            filters.append(Analysis.org_id == org_id)

        threat_case = case(
            (
                or_(
                    Analysis.verdict.in_(
                        [
                            AnalysisVerdict.MALICIOUS,
                            AnalysisVerdict.SUSPICIOUS,
                            AnalysisVerdict.QUARANTINE,
                            AnalysisVerdict.BLOCK,
                        ]
                    ),
                    Analysis.overall_risk_score >= 50,
                ),
                1,
            )
        )

        stmt = (
            select(
                time_bucket,
                func.count(Analysis.id).label("total"),
                func.count(threat_case).label("threats"),
            )
            .where(*filters)
            .group_by(time_bucket)
            .order_by(time_bucket.asc())
        )
        res = await self.session.execute(stmt)
        points: list[DetectionRatePoint] = []
        for r in res.all():
            total = r.total or 0
            threats = r.threats or 0
            rate = round((threats / total * 100.0), 2) if total > 0 else 0.0
            points.append(
                DetectionRatePoint(
                    timestamp=r.time_bucket,
                    total_analyzed=total,
                    threats_detected=threats,
                    detection_rate=rate,
                )
            )
        return points

    async def _false_positive_stats(
        self,
        org_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> FalsePositiveStats:
        """Calculate false positive rates based on user feedback threat signals."""
        filters: list[Any] = [
            ThreatSignal.source_engine == "user_feedback",
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= start,
            Analysis.created_at <= end,
        ]
        if org_id is not None:
            filters.append(Analysis.org_id == org_id)

        stmt = (
            select(
                func.count(ThreatSignal.id).label("reported_count"),
                func.count(
                    case(
                        (
                            ThreatSignal.signal_type.in_(
                                ["false_positive", "fp", "user_reported_fp"]
                            ),
                            1,
                        )
                    )
                ).label("specific_fp_count"),
            )
            .join(Analysis, ThreatSignal.analysis_id == Analysis.id)
            .where(*filters)
        )
        res = await self.session.execute(stmt)
        row = res.first()

        reported = row.reported_count if row and row.reported_count is not None else 0
        specific_fp = row.specific_fp_count if row and row.specific_fp_count is not None else 0
        confirmed = specific_fp if specific_fp > 0 else reported

        # Calculate total threats to compute rate
        threat_filters: list[Any] = [
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= start,
            Analysis.created_at <= end,
            or_(
                Analysis.verdict.in_(
                    [
                        AnalysisVerdict.MALICIOUS,
                        AnalysisVerdict.SUSPICIOUS,
                        AnalysisVerdict.QUARANTINE,
                        AnalysisVerdict.BLOCK,
                    ]
                ),
                Analysis.overall_risk_score >= 50,
            ),
        ]
        if org_id is not None:
            threat_filters.append(Analysis.org_id == org_id)

        threat_stmt = select(func.count(Analysis.id)).where(*threat_filters)
        total_threats = (await self.session.execute(threat_stmt)).scalar_one_or_none() or 0
        fp_rate = round((confirmed / total_threats * 100.0), 2) if total_threats > 0 else 0.0

        return FalsePositiveStats(
            reported_count=reported,
            confirmed_false_positive=confirmed,
            false_positive_rate=fp_rate,
        )

    async def _ml_performance(
        self,
        org_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> MLPerformanceMetrics:
        """Aggregate model performance, confidence, and class distribution for ML classifiers."""
        filters: list[Any] = [
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= start,
            Analysis.created_at <= end,
        ]
        if org_id is not None:
            filters.append(Analysis.org_id == org_id)

        stmt = (
            select(
                func.count(MLPrediction.id).label("total"),
                func.avg(MLPrediction.confidence_score).label("avg_confidence"),
                func.avg(MLPrediction.latency_ms).label("avg_latency"),
                func.count(case((MLPrediction.prediction_label == "phishing", 1))).label(
                    "phishing"
                ),
                func.count(case((MLPrediction.prediction_label == "clean", 1))).label("clean"),
                func.count(case((MLPrediction.prediction_label == "spam", 1))).label("spam"),
                func.count(case((MLPrediction.prediction_label == "malware", 1))).label("malware"),
            )
            .join(Analysis, MLPrediction.analysis_id == Analysis.id)
            .where(*filters)
        )
        res = await self.session.execute(stmt)
        row = res.first()

        total = row.total if row and row.total is not None else 0
        avg_conf = (
            round(float(row.avg_confidence), 4) if row and row.avg_confidence is not None else 0.0
        )
        avg_lat = round(float(row.avg_latency), 2) if row and row.avg_latency is not None else 0.0
        phishing = row.phishing if row and row.phishing is not None else 0
        clean = row.clean if row and row.clean is not None else 0
        spam = row.spam if row and row.spam is not None else 0
        malware = row.malware if row and row.malware is not None else 0

        return MLPerformanceMetrics(
            total_predictions=total,
            avg_confidence=avg_conf,
            avg_latency_ms=avg_lat,
            phishing_detected=phishing,
            clean_detected=clean,
            spam_detected=spam,
            malware_detected=malware,
        )

    async def _llm_utilization(
        self,
        org_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> LLMUtilizationMetrics:
        """Aggregate LLM inference telemetry, token usage, and safety compliance."""
        filters: list[Any] = [
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= start,
            Analysis.created_at <= end,
        ]
        if org_id is not None:
            filters.append(Analysis.org_id == org_id)

        prompt_tokens = func.coalesce(
            func.sum(cast(LLMAnalysis.token_usage["prompt"].as_string(), Integer)), 0
        ).label("prompt_tokens")
        completion_tokens = func.coalesce(
            func.sum(cast(LLMAnalysis.token_usage["completion"].as_string(), Integer)), 0
        ).label("completion_tokens")
        total_tokens = func.coalesce(
            func.sum(cast(LLMAnalysis.token_usage["total"].as_string(), Integer)), 0
        ).label("total_tokens")

        stmt = (
            select(
                func.count(LLMAnalysis.id).label("total_calls"),
                func.avg(LLMAnalysis.confidence_score).label("avg_confidence"),
                func.avg(LLMAnalysis.latency_ms).label("avg_latency"),
                func.count(case((LLMAnalysis.safety_passed.is_(True), 1))).label(
                    "safety_passed_count"
                ),
                prompt_tokens,
                completion_tokens,
                total_tokens,
            )
            .join(Analysis, LLMAnalysis.analysis_id == Analysis.id)
            .where(*filters)
        )
        res = await self.session.execute(stmt)
        row = res.first()

        total = row.total_calls if row and row.total_calls is not None else 0
        avg_conf = (
            round(float(row.avg_confidence), 4) if row and row.avg_confidence is not None else 0.0
        )
        avg_lat = round(float(row.avg_latency), 2) if row and row.avg_latency is not None else 0.0
        safety_passed = (
            row.safety_passed_count if row and row.safety_passed_count is not None else 0
        )
        safety_rate = round((safety_passed / total * 100.0), 2) if total > 0 else 100.0
        p_tokens = int(row.prompt_tokens) if row and row.prompt_tokens is not None else 0
        c_tokens = int(row.completion_tokens) if row and row.completion_tokens is not None else 0
        t_tokens = int(row.total_tokens) if row and row.total_tokens is not None else 0

        # Model breakdown
        model_stmt = (
            select(
                LLMAnalysis.model_name,
                func.count(LLMAnalysis.id).label("count"),
            )
            .join(Analysis, LLMAnalysis.analysis_id == Analysis.id)
            .where(*filters)
            .group_by(LLMAnalysis.model_name)
        )
        model_res = await self.session.execute(model_stmt)
        models_breakdown = {m: c for m, c in model_res.all() if m}

        return LLMUtilizationMetrics(
            total_calls=total,
            avg_confidence=avg_conf,
            avg_latency_ms=avg_lat,
            total_prompt_tokens=p_tokens,
            total_completion_tokens=c_tokens,
            total_tokens=t_tokens,
            safety_pass_rate=safety_rate,
            models_breakdown=models_breakdown,
        )

    async def _processing_latency(
        self,
        org_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> ProcessingLatencyStats:
        """Calculate latency percentiles and distribution statistics for completed pipeline executions."""
        filters: list[Any] = [
            Analysis.duration_ms.is_not(None),
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= start,
            Analysis.created_at <= end,
        ]
        if org_id is not None:
            filters.append(Analysis.org_id == org_id)

        count_stmt = select(func.count(Analysis.id)).where(*filters)
        count_res = await self.session.execute(count_stmt)
        row_count = count_res.scalar_one_or_none() or 0

        if row_count == 0:
            return ProcessingLatencyStats(
                p50_ms=0.0,
                p90_ms=0.0,
                p95_ms=0.0,
                p99_ms=0.0,
                avg_ms=0.0,
                min_ms=0.0,
                max_ms=0.0,
            )

        latency_stmt = select(
            func.percentile_cont(0.50).within_group(Analysis.duration_ms.asc()).label("p50"),
            func.percentile_cont(0.90).within_group(Analysis.duration_ms.asc()).label("p90"),
            func.percentile_cont(0.95).within_group(Analysis.duration_ms.asc()).label("p95"),
            func.percentile_cont(0.99).within_group(Analysis.duration_ms.asc()).label("p99"),
            func.avg(Analysis.duration_ms).label("avg"),
            func.min(Analysis.duration_ms).label("min"),
            func.max(Analysis.duration_ms).label("max"),
        ).where(*filters)

        res = await self.session.execute(latency_stmt)
        row = res.first()

        p50 = round(float(row.p50), 2) if row and row.p50 is not None else 0.0
        p90 = round(float(row.p90), 2) if row and row.p90 is not None else 0.0
        p95 = round(float(row.p95), 2) if row and row.p95 is not None else 0.0
        p99 = round(float(row.p99), 2) if row and row.p99 is not None else 0.0
        avg_lat = round(float(row.avg), 2) if row and row.avg is not None else 0.0
        min_lat = float(row.min) if row and row.min is not None else 0.0
        max_lat = float(row.max) if row and row.max is not None else 0.0

        return ProcessingLatencyStats(
            p50_ms=p50,
            p90_ms=p90,
            p95_ms=p95,
            p99_ms=p99,
            avg_ms=avg_lat,
            min_ms=min_lat,
            max_ms=max_lat,
        )

    async def _threat_intel_usage(
        self,
        org_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> ThreatIntelUsageStats:
        """Query external threat intelligence hit rates and vendor breakdown."""
        filters: list[Any] = [
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= start,
            Analysis.created_at <= end,
        ]
        if org_id is not None:
            filters.append(Analysis.org_id == org_id)

        stmt = (
            select(
                func.count(ThreatIntelligenceResult.id).label("total_queries"),
                func.count(
                    case(
                        (
                            ThreatIntelligenceResult.reputation_verdict
                            == ReputationVerdict.MALICIOUS,
                            1,
                        )
                    )
                ).label("malicious_hits"),
                func.count(
                    case(
                        (
                            ThreatIntelligenceResult.reputation_verdict
                            == ReputationVerdict.SUSPICIOUS,
                            1,
                        )
                    )
                ).label("suspicious_hits"),
                func.count(
                    case(
                        (
                            ThreatIntelligenceResult.reputation_verdict == ReputationVerdict.CLEAN,
                            1,
                        )
                    )
                ).label("clean_hits"),
                func.count(
                    case(
                        (
                            ThreatIntelligenceResult.reputation_verdict
                            == ReputationVerdict.UNKNOWN,
                            1,
                        )
                    )
                ).label("unknown_hits"),
            )
            .join(Analysis, ThreatIntelligenceResult.analysis_id == Analysis.id)
            .where(*filters)
        )
        res = await self.session.execute(stmt)
        row = res.first()

        total = row.total_queries if row and row.total_queries is not None else 0
        malicious = row.malicious_hits if row and row.malicious_hits is not None else 0
        suspicious = row.suspicious_hits if row and row.suspicious_hits is not None else 0
        clean = row.clean_hits if row and row.clean_hits is not None else 0
        unknown = row.unknown_hits if row and row.unknown_hits is not None else 0

        provider_stmt = (
            select(
                ThreatIntelligenceResult.provider,
                func.count(ThreatIntelligenceResult.id).label("count"),
            )
            .join(Analysis, ThreatIntelligenceResult.analysis_id == Analysis.id)
            .where(*filters)
            .group_by(ThreatIntelligenceResult.provider)
        )
        p_res = await self.session.execute(provider_stmt)
        providers_breakdown = {p: c for p, c in p_res.all() if p}

        return ThreatIntelUsageStats(
            total_queries=total,
            malicious_hits=malicious,
            suspicious_hits=suspicious,
            clean_hits=clean,
            unknown_hits=unknown,
            providers_breakdown=providers_breakdown,
        )
