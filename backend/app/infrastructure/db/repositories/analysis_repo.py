"""Repository for security analysis pipelines, verdicts, and nested ML/LLM/Risk records."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.infrastructure.db.models.analysis import (
    Analysis,
    AnalysisEvent,
    LLMAnalysis,
    MLPrediction,
    RiskScore,
    ThreatSignal,
)
from app.infrastructure.db.models.email import Email
from app.infrastructure.db.models.enums import (
    AnalysisStatus,
    AnalysisVerdict,
    AttackType,
    RiskLevel,
)
from app.infrastructure.db.repositories.base import BaseRepository


class AnalysisRepository(BaseRepository[Analysis]):
    """Data access layer for security analyses."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Analysis, session)

    async def get_by_email_id(self, email_id: uuid.UUID) -> Analysis | None:
        """Find analysis linked to an email."""
        stmt = (
            select(Analysis)
            .where(Analysis.email_id == email_id)
            .where(Analysis.deleted_at.is_(None))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_with_full_details(
        self,
        analysis_id: uuid.UUID,
        *,
        include_events: bool = True,
    ) -> Analysis | None:
        """Fetch complete analysis record with all sub-engines and forensic results."""
        options = [
            selectinload(Analysis.email).selectinload(Email.header),
            selectinload(Analysis.email).selectinload(Email.urls),
            selectinload(Analysis.email).selectinload(Email.attachments),
            selectinload(Analysis.risk_score),
            selectinload(Analysis.ml_prediction),
            selectinload(Analysis.llm_analysis),
            selectinload(Analysis.threat_signals),
            selectinload(Analysis.threat_intel_results),
        ]
        if include_events:
            options.append(selectinload(Analysis.events))

        stmt = (
            select(Analysis)
            .options(*options)
            .where(Analysis.id == analysis_id)
            .where(Analysis.deleted_at.is_(None))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_events(self, analysis_id: uuid.UUID) -> list[AnalysisEvent]:
        """Fetch only the stage event log for an analysis without loading other relations."""
        stmt = (
            select(AnalysisEvent)
            .where(AnalysisEvent.analysis_id == analysis_id)
            .order_by(AnalysisEvent.created_at.asc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_history(
        self,
        org_id: uuid.UUID,
        *,
        verdict: AnalysisVerdict | None = None,
        risk_level: RiskLevel | None = None,
        min_risk_score: int | None = None,
        status: AnalysisStatus | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Sequence[Analysis]:
        """Query analysis history with optimized filtering."""
        stmt = (
            select(Analysis)
            .options(selectinload(Analysis.email), selectinload(Analysis.risk_score))
            .where(Analysis.org_id == org_id)
            .where(Analysis.deleted_at.is_(None))
        )
        if status is not None:
            stmt = stmt.where(Analysis.status == status)
        if verdict is not None:
            stmt = stmt.where(Analysis.verdict == verdict)
        if risk_level is not None:
            stmt = stmt.where(Analysis.risk_level == risk_level)
        if min_risk_score is not None:
            stmt = stmt.where(Analysis.overall_risk_score >= min_risk_score)

        stmt = stmt.order_by(Analysis.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def record_completion(
        self,
        analysis_id: uuid.UUID,
        *,
        verdict: AnalysisVerdict,
        overall_risk_score: int,
        risk_level: RiskLevel,
        duration_ms: int,
    ) -> Analysis | None:
        """Mark analysis as successfully completed with final scores."""
        analysis = await self.get_by_id(analysis_id)
        if analysis:
            analysis.status = AnalysisStatus.COMPLETE
            analysis.verdict = verdict
            analysis.overall_risk_score = overall_risk_score
            analysis.risk_level = risk_level
            analysis.completed_at = datetime.now(UTC)
            analysis.duration_ms = duration_ms
            await self.session.flush()
        return analysis

    async def record_failure(
        self,
        analysis_id: uuid.UUID,
        *,
        error_message: str,
    ) -> Analysis | None:
        """Mark analysis as failed with error diagnosis."""
        analysis = await self.get_by_id(analysis_id)
        if analysis:
            analysis.status = AnalysisStatus.FAILED
            analysis.error_message = error_message
            analysis.completed_at = datetime.now(UTC)
            analysis.retry_count += 1
            await self.session.flush()
        return analysis

    async def save_risk_score(self, risk_score: RiskScore) -> RiskScore:
        """Persist authoritative risk score."""
        self.session.add(risk_score)
        await self.session.flush()
        return risk_score

    async def save_ml_prediction(self, ml_prediction: MLPrediction) -> MLPrediction:
        """Persist ML classification output."""
        self.session.add(ml_prediction)
        await self.session.flush()
        return ml_prediction

    async def save_llm_analysis(self, llm_analysis: LLMAnalysis) -> LLMAnalysis:
        """Persist LLM threat narrative."""
        self.session.add(llm_analysis)
        await self.session.flush()
        return llm_analysis

    async def record_event(self, event: AnalysisEvent) -> AnalysisEvent:
        """Append an analysis lifecycle event."""
        self.session.add(event)
        await self.session.flush()
        return event

    async def get_paginated_history(
        self,
        org_id: uuid.UUID,
        *,
        page: int = 1,
        page_size: int = 20,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        search: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        severity: RiskLevel | None = None,
        attack_type: AttackType | None = None,
        sender: str | None = None,
        min_risk_score: int | None = None,
        max_risk_score: int | None = None,
        status: AnalysisStatus | None = None,
        classification: AnalysisVerdict | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Fetch server-side filtered, sorted, and paginated analysis history records."""
        stmt = (
            select(Analysis)
            .join(Email, Analysis.email_id == Email.id)
            .options(selectinload(Analysis.email), selectinload(Analysis.threat_signals))
            .where(Analysis.org_id == org_id)
            .where(Analysis.deleted_at.is_(None))
        )
        count_stmt = (
            select(func.count(distinct(Analysis.id)))
            .select_from(Analysis)
            .join(Email, Analysis.email_id == Email.id)
            .where(Analysis.org_id == org_id)
            .where(Analysis.deleted_at.is_(None))
        )

        conditions = []
        if status is not None:
            conditions.append(Analysis.status == status)
        if classification is not None:
            conditions.append(Analysis.verdict == classification)
        if severity is not None:
            conditions.append(Analysis.risk_level == severity)
        if min_risk_score is not None:
            conditions.append(Analysis.overall_risk_score >= min_risk_score)
        if max_risk_score is not None:
            conditions.append(Analysis.overall_risk_score <= max_risk_score)
        if start_date is not None:
            conditions.append(Analysis.created_at >= start_date)
        if end_date is not None:
            conditions.append(Analysis.created_at <= end_date)
        if sender and sender.strip():
            term = f"%{sender.strip()}%"
            conditions.append(
                or_(
                    Email.from_address.ilike(term),
                    Email.from_domain.ilike(term),
                )
            )
        if search and search.strip():
            sterm = f"%{search.strip()}%"
            conditions.append(
                or_(
                    Email.from_address.ilike(sterm),
                    Email.from_domain.ilike(sterm),
                    Email.subject.ilike(sterm),
                )
            )
        if attack_type is not None:
            # Use EXISTS instead of IN subquery — avoids materializing IDs and
            # short-circuits on first matching threat signal
            from sqlalchemy import exists

            subq = (
                select(ThreatSignal.analysis_id)
                .where(ThreatSignal.attack_type == attack_type)
                .where(ThreatSignal.analysis_id == Analysis.id)
            )
            conditions.append(exists(subq))

        for cond in conditions:
            stmt = stmt.where(cond)
            count_stmt = count_stmt.where(cond)

        total_count = await self.session.scalar(count_stmt) or 0

        sort_map = {
            "timestamp": Analysis.created_at,
            "created_at": Analysis.created_at,
            "risk_score": Analysis.overall_risk_score,
            "risk": Analysis.overall_risk_score,
            "severity": Analysis.risk_level,
            "sender": Email.from_address,
            "subject": Email.subject,
            "status": Analysis.status,
            "classification": Analysis.verdict,
        }
        col = sort_map.get(sort_by.lower(), Analysis.created_at)
        if sort_order.lower() == "asc":
            stmt = stmt.order_by(col.asc().nulls_last())
        else:
            stmt = stmt.order_by(col.desc().nulls_last())

        offset = max(0, (page - 1) * page_size)
        stmt = stmt.offset(offset).limit(page_size)

        result = await self.session.execute(stmt)
        analyses = result.scalars().all()

        status_mapping = {
            AnalysisStatus.QUEUED: "queued",
            AnalysisStatus.ANALYZING: "processing",
            AnalysisStatus.COMPLETE: "completed",
            AnalysisStatus.FAILED: "failed",
            AnalysisStatus.SKIPPED: "failed",
        }

        items: list[dict[str, Any]] = []
        for a in analyses:
            top_attack = "none"
            if a.threat_signals:
                meaningful = [
                    s
                    for s in a.threat_signals
                    if s.attack_type and s.attack_type.value not in ("none", "unknown")
                ]
                if meaningful:
                    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                    meaningful.sort(key=lambda s: sev_rank.get(s.severity.value, 5))
                    top_attack = meaningful[0].attack_type.value
                else:
                    top_attack = a.threat_signals[0].attack_type.value

            items.append(
                {
                    "analysis_id": str(a.id),
                    "email_id": str(a.email_id),
                    "timestamp": a.created_at,
                    "sender": a.email.from_address if a.email else "unknown",
                    "sender_domain": a.email.from_domain if a.email else "unknown",
                    "subject": a.email.subject if a.email and a.email.subject else "(No Subject)",
                    "classification": a.verdict.value if a.verdict else "unknown",
                    "severity": a.risk_level.value if a.risk_level else "safe",
                    "risk_score": a.overall_risk_score or 0,
                    "status": status_mapping.get(a.status, "unknown"),
                    "attack_type": top_attack,
                    "duration_ms": a.duration_ms,
                }
            )

        return items, total_count
