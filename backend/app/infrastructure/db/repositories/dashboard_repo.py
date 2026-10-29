"""Authoritative PostgreSQL aggregation repository for Dashboard metrics and charts."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.schemas.dashboard import (
    AttackTypeItem,
    DashboardChartsResponse,
    DashboardMetricsResponse,
    DetectionTrendPoint,
    LatencyDistributionBucket,
    LLMUsageMetric,
    RecentThreatItem,
    RiskDistributionBucket,
    SeverityDistributionItem,
    ThreatTimelinePoint,
)
from app.infrastructure.db.models.analysis import (
    Analysis,
    LLMAnalysis,
    ThreatSignal,
)
from app.infrastructure.db.models.email import Attachment
from app.infrastructure.db.models.enums import (
    AnalysisStatus,
    AnalysisVerdict,
    AttackType,
    RiskLevel,
    ThreatCategory,
)


class DashboardRepository:
    """Computes all production security dashboard metrics directly via PostgreSQL queries."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_metrics(self, org_id: uuid.UUID | None = None) -> DashboardMetricsResponse:
        """Fetch all 12 key dashboard metrics in real-time from PostgreSQL."""
        # 1. Base query for analyses
        analysis_filter: list[Any] = [Analysis.deleted_at.is_(None)]
        if org_id is not None:
            analysis_filter.append(Analysis.org_id == org_id)

        # Total analyses & status counts
        total_stmt = select(
            func.count(Analysis.id).label("total"),
            func.count(case((Analysis.status == AnalysisStatus.COMPLETE, 1))).label("completed"),
            func.count(case((Analysis.status == AnalysisStatus.FAILED, 1))).label("failed"),
            func.avg(
                case(
                    (
                        Analysis.status == AnalysisStatus.COMPLETE,
                        Analysis.overall_risk_score,
                    )
                )
            ).label("avg_risk"),
            func.avg(
                case(
                    (
                        Analysis.status == AnalysisStatus.COMPLETE,
                        Analysis.duration_ms,
                    )
                )
            ).label("avg_latency"),
            func.count(
                case(
                    (
                        or_(
                            Analysis.verdict.in_(
                                [
                                    AnalysisVerdict.MALICIOUS,
                                    AnalysisVerdict.SUSPICIOUS,
                                    AnalysisVerdict.BLOCK,
                                    AnalysisVerdict.QUARANTINE,
                                ]
                            ),
                            Analysis.overall_risk_score >= 50,
                        ),
                        1,
                    )
                )
            ).label("threats"),
            func.count(
                case(
                    (
                        or_(
                            Analysis.risk_level == RiskLevel.HIGH,
                            Analysis.overall_risk_score.between(70, 89),
                        ),
                        1,
                    )
                )
            ).label("high_risk"),
            func.count(
                case(
                    (
                        or_(
                            Analysis.risk_level == RiskLevel.CRITICAL,
                            Analysis.overall_risk_score >= 90,
                        ),
                        1,
                    )
                )
            ).label("critical"),
        ).where(*analysis_filter)
        total_res = await self.session.execute(total_stmt)
        row = total_res.first()

        total = row.total if row and row.total is not None else 0
        completed = row.completed if row and row.completed is not None else 0
        threats = row.threats if row and row.threats is not None else 0
        high_risk = row.high_risk if row and row.high_risk is not None else 0
        critical = row.critical if row and row.critical is not None else 0
        avg_risk = float(row.avg_risk) if row and row.avg_risk is not None else 0.0
        avg_latency = float(row.avg_latency) if row and row.avg_latency is not None else 0.0

        success_rate = round((completed / total * 100.0), 1) if total > 0 else 100.0

        # 2. Threat signal counts
        sig_filter = []
        if org_id is not None:
            sig_filter.append(ThreatSignal.org_id == org_id)

        sig_stmt = select(
            func.count(
                case(
                    (
                        or_(
                            ThreatSignal.category == ThreatCategory.PHISHING,
                            ThreatSignal.attack_type.in_(
                                [
                                    AttackType.SPEAR_PHISHING,
                                    AttackType.CLONE_PHISHING,
                                    AttackType.WHALING,
                                    AttackType.CALLBACK_PHISHING,
                                ]
                            ),
                        ),
                        1,
                    )
                )
            ).label("phishing"),
            func.count(
                case(
                    (
                        or_(
                            ThreatSignal.category == ThreatCategory.BUSINESS_EMAIL_COMPROMISE,
                            ThreatSignal.attack_type.in_(
                                [
                                    AttackType.WHALING,
                                    AttackType.SPEAR_PHISHING,
                                ]
                            ),
                        ),
                        1,
                    )
                )
            ).label("bec"),
            func.count(
                case(
                    (
                        or_(
                            ThreatSignal.category == ThreatCategory.CREDENTIAL_THEFT,
                            ThreatSignal.attack_type == AttackType.CREDENTIAL_HARVESTING,
                        ),
                        1,
                    )
                )
            ).label("credentials"),
            func.count(
                case(
                    (
                        or_(
                            ThreatSignal.category == ThreatCategory.MALWARE,
                            ThreatSignal.attack_type.in_(
                                [
                                    AttackType.MALICIOUS_DOCUMENT,
                                    AttackType.RANSOMWARE_DELIVERY,
                                ]
                            ),
                        ),
                        1,
                    )
                )
            ).label("malware"),
        ).where(*sig_filter)
        sig_res = await self.session.execute(sig_stmt)
        sig_row = sig_res.first()

        phishing = sig_row.phishing if sig_row and sig_row.phishing is not None else 0
        bec = sig_row.bec if sig_row and sig_row.bec is not None else 0
        credentials = sig_row.credentials if sig_row and sig_row.credentials is not None else 0
        malware = sig_row.malware if sig_row and sig_row.malware is not None else 0

        # Also add executable attachments count to malware events if present
        att_stmt = select(func.count(Attachment.id)).where(Attachment.is_executable.is_(True))
        att_res = await self.session.execute(att_stmt)
        executable_attachments = att_res.scalar_one_or_none() or 0
        malware += executable_attachments

        # 3. LLM usage metrics
        if org_id is not None:
            # Join with analysis to check org_id
            llm_stmt = (
                select(
                    func.count(LLMAnalysis.id).label("total_llm"),
                    func.avg(LLMAnalysis.latency_ms).label("avg_llm_latency"),
                )
                .join(Analysis, LLMAnalysis.analysis_id == Analysis.id)
                .where(Analysis.org_id == org_id)
            )
        else:
            llm_stmt = select(
                func.count(LLMAnalysis.id).label("total_llm"),
                func.avg(LLMAnalysis.latency_ms).label("avg_llm_latency"),
            )

        llm_res = await self.session.execute(llm_stmt)
        llm_row = llm_res.first()
        total_llm = llm_row.total_llm if llm_row and llm_row.total_llm is not None else 0
        avg_llm_lat = (
            float(llm_row.avg_llm_latency)
            if llm_row and llm_row.avg_llm_latency is not None
            else 0.0
        )

        # LLM Model breakdown
        model_stmt = select(LLMAnalysis.model_name, func.count(LLMAnalysis.id)).group_by(
            LLMAnalysis.model_name
        )
        model_res = await self.session.execute(model_stmt)
        model_breakdown = {m: c for m, c in model_res.all() if m}

        # Calculate skipped calls from total analyses vs llm analyses
        skipped = max(0, total - total_llm)

        llm_metric = LLMUsageMetric(
            total_calls=total_llm + skipped,
            analyzed_calls=total_llm,
            skipped_calls=skipped,
            average_latency_ms=round(avg_llm_lat, 1),
            models_breakdown=model_breakdown,
        )

        return DashboardMetricsResponse(
            total_emails_analyzed=total,
            threats_detected=threats,
            high_risk_emails=high_risk,
            critical_threats=critical,
            phishing_count=phishing,
            bec_count=bec,
            credential_theft_count=credentials,
            malware_related_events=malware,
            average_risk_score=round(avg_risk, 1),
            analysis_success_rate=success_rate,
            llm_usage=llm_metric,
            average_analysis_latency_ms=round(avg_latency, 1),
        )

    async def get_charts_data(
        self,
        org_id: uuid.UUID | None = None,
        days: int = 14,
    ) -> DashboardChartsResponse:
        """Fetch all 8 production dashboard visualizations backed by PostgreSQL queries."""
        now = datetime.now(UTC)
        cutoff_date = (now - timedelta(days=days)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

        # -------------------------------------------------------------------
        # 1. Threats over time & 7. Detection trends
        # -------------------------------------------------------------------
        analysis_filter = [
            Analysis.deleted_at.is_(None),
            Analysis.created_at >= cutoff_date,
        ]
        if org_id is not None:
            analysis_filter.append(Analysis.org_id == org_id)

        time_stmt = (
            select(
                Analysis.created_at,
                Analysis.verdict,
                Analysis.overall_risk_score,
            )
            .where(*analysis_filter)
            .order_by(Analysis.created_at.asc())
        )
        time_res = await self.session.execute(time_stmt)
        rows = time_res.all()

        # Group rows by date YYYY-MM-DD
        daily_buckets: dict[str, dict[str, int]] = defaultdict(
            lambda: {"clean": 0, "suspicious": 0, "malicious": 0, "total": 0}
        )

        # Initialize all days in the window to ensure no missing dates
        cur = cutoff_date
        while cur <= now:
            daily_buckets[cur.strftime("%Y-%m-%d")] = {
                "clean": 0,
                "suspicious": 0,
                "malicious": 0,
                "total": 0,
            }
            cur += timedelta(days=1)

        for created_at, verdict, score in rows:
            if not created_at:
                continue
            date_key = created_at.strftime("%Y-%m-%d")
            daily_buckets[date_key]["total"] += 1

            v_val = (
                verdict.value
                if verdict is not None and hasattr(verdict, "value")
                else str(verdict or "")
            )
            if v_val == "clean" or (score is not None and score < 30):
                daily_buckets[date_key]["clean"] += 1
            elif v_val == "suspicious" or (score is not None and 30 <= score < 70):
                daily_buckets[date_key]["suspicious"] += 1
            elif v_val in ("malicious", "quarantine", "block") or (
                score is not None and score >= 70
            ):
                daily_buckets[date_key]["malicious"] += 1
            else:
                daily_buckets[date_key]["clean"] += 1

        threats_over_time = [
            ThreatTimelinePoint(
                date=k,
                clean=v["clean"],
                suspicious=v["suspicious"],
                malicious=v["malicious"],
                total=v["total"],
            )
            for k, v in sorted(daily_buckets.items())
        ]

        # Detection trend line points
        detection_trends = [
            DetectionTrendPoint(
                date=p.date,
                detection_rate_pct=round(
                    ((p.suspicious + p.malicious) / p.total * 100.0) if p.total > 0 else 0.0,
                    1,
                ),
                volume=p.total,
            )
            for p in threats_over_time
        ]

        # -------------------------------------------------------------------
        # 2. Risk distribution
        # -------------------------------------------------------------------
        risk_filter: list[Any] = [Analysis.deleted_at.is_(None)]
        if org_id is not None:
            risk_filter.append(Analysis.org_id == org_id)

        risk_stmt = select(
            func.count(
                case(
                    (
                        or_(
                            Analysis.risk_level == RiskLevel.SAFE,
                            Analysis.overall_risk_score.between(0, 19),
                        ),
                        1,
                    )
                )
            ).label("safe"),
            func.count(
                case(
                    (
                        or_(
                            Analysis.risk_level == RiskLevel.LOW,
                            Analysis.overall_risk_score.between(20, 39),
                        ),
                        1,
                    )
                )
            ).label("low"),
            func.count(
                case(
                    (
                        or_(
                            Analysis.risk_level == RiskLevel.MEDIUM,
                            Analysis.overall_risk_score.between(40, 69),
                        ),
                        1,
                    )
                )
            ).label("medium"),
            func.count(
                case(
                    (
                        or_(
                            Analysis.risk_level == RiskLevel.HIGH,
                            Analysis.overall_risk_score.between(70, 89),
                        ),
                        1,
                    )
                )
            ).label("high"),
            func.count(
                case(
                    (
                        or_(
                            Analysis.risk_level == RiskLevel.CRITICAL,
                            Analysis.overall_risk_score >= 90,
                        ),
                        1,
                    )
                )
            ).label("critical"),
        ).where(*risk_filter)

        risk_res = await self.session.execute(risk_stmt)
        r_row = risk_res.first()

        risk_distribution = [
            RiskDistributionBucket(
                tier="Safe (0-19)",
                count=r_row.safe if r_row and r_row.safe is not None else 0,
                color="#22c55e",
            ),
            RiskDistributionBucket(
                tier="Low (20-39)",
                count=r_row.low if r_row and r_row.low is not None else 0,
                color="#8b5cf6",
            ),
            RiskDistributionBucket(
                tier="Medium (40-69)",
                count=r_row.medium if r_row and r_row.medium is not None else 0,
                color="#f59e0b",
            ),
            RiskDistributionBucket(
                tier="High (70-89)",
                count=r_row.high if r_row and r_row.high is not None else 0,
                color="#f97316",
            ),
            RiskDistributionBucket(
                tier="Critical (90-100)",
                count=r_row.critical if r_row and r_row.critical is not None else 0,
                color="#dc2626",
            ),
        ]

        # -------------------------------------------------------------------
        # 3. Attack type distribution
        # -------------------------------------------------------------------
        atk_filter = []
        if org_id is not None:
            atk_filter.append(ThreatSignal.org_id == org_id)

        atk_stmt = (
            select(ThreatSignal.attack_type, func.count(ThreatSignal.id))
            .where(*atk_filter)
            .group_by(ThreatSignal.attack_type)
            .order_by(func.count(ThreatSignal.id).desc())
        )
        atk_res = await self.session.execute(atk_stmt)
        atk_data = atk_res.all()
        total_atk = sum(c for _, c in atk_data) or 1

        attack_type_distribution = [
            AttackTypeItem(
                attack_type=(
                    at.value.replace("_", " ").title()
                    if hasattr(at, "value")
                    else str(at or "Unknown").replace("_", " ").title()
                ),
                count=c,
                percentage=round(c / total_atk * 100.0, 1),
            )
            for at, c in atk_data
            if at != AttackType.UNKNOWN and c > 0
        ]

        # -------------------------------------------------------------------
        # 4. Severity distribution
        # -------------------------------------------------------------------
        sev_stmt = (
            select(ThreatSignal.severity, func.count(ThreatSignal.id))
            .where(*atk_filter)
            .group_by(ThreatSignal.severity)
        )
        sev_res = await self.session.execute(sev_stmt)
        sev_counts = {(s.value if hasattr(s, "value") else str(s)): c for s, c in sev_res.all()}

        severity_colors = {
            "critical": "#dc2626",
            "high": "#f97316",
            "medium": "#f59e0b",
            "low": "#8b5cf6",
            "info": "#14b8a6",
        }

        severity_distribution = [
            SeverityDistributionItem(
                severity=sev.title(),
                count=sev_counts.get(sev, 0),
                color=severity_colors.get(sev, "#8b5cf6"),
            )
            for sev in ["critical", "high", "medium", "low", "info"]
        ]

        # -------------------------------------------------------------------
        # 5. Analysis processing time
        # -------------------------------------------------------------------
        proc_stmt = select(
            func.count(case((Analysis.duration_ms < 500, 1))).label("lt_500"),
            func.count(case((Analysis.duration_ms.between(500, 1000), 1))).label(
                "between_500_1000"
            ),
            func.count(case((Analysis.duration_ms.between(1001, 2000), 1))).label(
                "between_1000_2000"
            ),
            func.count(case((Analysis.duration_ms.between(2001, 5000), 1))).label(
                "between_2000_5000"
            ),
            func.count(case((Analysis.duration_ms > 5000, 1))).label("gt_5000"),
        ).where(
            Analysis.deleted_at.is_(None),
            Analysis.status == AnalysisStatus.COMPLETE,
            Analysis.duration_ms.is_not(None),
        )
        if org_id is not None:
            proc_stmt = proc_stmt.where(Analysis.org_id == org_id)

        proc_res = await self.session.execute(proc_stmt)
        p_row = proc_res.first()

        processing_time_distribution = [
            LatencyDistributionBucket(
                bucket="< 500ms",
                count=p_row.lt_500 if p_row and p_row.lt_500 is not None else 0,
            ),
            LatencyDistributionBucket(
                bucket="500ms - 1s",
                count=p_row.between_500_1000 if p_row and p_row.between_500_1000 is not None else 0,
            ),
            LatencyDistributionBucket(
                bucket="1s - 2s",
                count=p_row.between_1000_2000
                if p_row and p_row.between_1000_2000 is not None
                else 0,
            ),
            LatencyDistributionBucket(
                bucket="2s - 5s",
                count=p_row.between_2000_5000
                if p_row and p_row.between_2000_5000 is not None
                else 0,
            ),
            LatencyDistributionBucket(
                bucket="> 5s",
                count=p_row.gt_5000 if p_row and p_row.gt_5000 is not None else 0,
            ),
        ]

        # -------------------------------------------------------------------
        # 6. LLM usage
        # -------------------------------------------------------------------
        metrics = await self.get_metrics(org_id)
        llm_usage = metrics.llm_usage

        # -------------------------------------------------------------------
        # 8. Recent threats
        # -------------------------------------------------------------------
        recent_threats = await self.get_recent_threats(org_id, limit=10)

        return DashboardChartsResponse(
            threats_over_time=threats_over_time,
            risk_distribution=risk_distribution,
            attack_type_distribution=attack_type_distribution,
            severity_distribution=severity_distribution,
            processing_time_distribution=processing_time_distribution,
            llm_usage=llm_usage,
            detection_trends=detection_trends,
            recent_threats=recent_threats,
        )

    async def get_recent_threats(
        self,
        org_id: uuid.UUID | None = None,
        limit: int = 20,
    ) -> list[RecentThreatItem]:
        """Fetch the most recent identified threats with full forensic details."""
        stmt = (
            select(Analysis)
            .options(
                selectinload(Analysis.email),
                selectinload(Analysis.threat_signals),
            )
            .where(Analysis.deleted_at.is_(None))
            .where(
                or_(
                    Analysis.verdict.in_(
                        [
                            AnalysisVerdict.MALICIOUS,
                            AnalysisVerdict.SUSPICIOUS,
                            AnalysisVerdict.BLOCK,
                            AnalysisVerdict.QUARANTINE,
                        ]
                    ),
                    Analysis.overall_risk_score >= 40,
                )
            )
            .order_by(Analysis.created_at.desc())
            .limit(limit)
        )
        if org_id is not None:
            stmt = stmt.where(Analysis.org_id == org_id)

        res = await self.session.execute(stmt)
        analyses = res.scalars().all()

        items: list[RecentThreatItem] = []
        for an in analyses:
            em = an.email
            if not em:
                continue

            # Pick top threat signal if available
            top_sig = (
                max(an.threat_signals, key=lambda s: s.confidence) if an.threat_signals else None
            )

            atk_type = (
                top_sig.attack_type.value.replace("_", " ").title()
                if top_sig and hasattr(top_sig.attack_type, "value")
                else "Unspecified Threat"
            )
            cat = (
                top_sig.category.value.replace("_", " ").title()
                if top_sig and hasattr(top_sig.category, "value")
                else "Phishing"
            )

            v_val = (
                an.verdict.value
                if an.verdict is not None and hasattr(an.verdict, "value")
                else str(an.verdict or "suspicious")
            )
            r_val = (
                an.risk_level.value
                if an.risk_level is not None and hasattr(an.risk_level, "value")
                else str(an.risk_level or "medium")
            )

            items.append(
                RecentThreatItem(
                    analysis_id=str(an.id),
                    email_id=str(em.id),
                    subject=em.subject or "(No Subject)",
                    from_address=em.from_address or "unknown@domain.com",
                    from_domain=em.from_domain or "unknown.domain",
                    risk_score=an.overall_risk_score or 0,
                    risk_level=r_val,
                    verdict=v_val,
                    attack_type=atk_type,
                    category=cat,
                    received_at=(em.received_at or an.created_at).isoformat(),
                    has_attachments=em.has_attachments or False,
                )
            )

        return items
