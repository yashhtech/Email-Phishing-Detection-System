"""Repositories for ThreatSignals and cached ThreatIntelligenceResults."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.models.analysis import ThreatIntelligenceResult, ThreatSignal
from app.infrastructure.db.models.enums import AttackType, ThreatSeverity
from app.infrastructure.db.repositories.base import BaseRepository


class ThreatSignalRepository(BaseRepository[ThreatSignal]):
    """Data access layer for specific security indicators and threat findings."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(ThreatSignal, session)

    async def list_by_analysis(self, analysis_id: uuid.UUID) -> Sequence[ThreatSignal]:
        """Fetch all findings for an analysis ordered by severity descending."""
        stmt = (
            select(ThreatSignal)
            .where(ThreatSignal.analysis_id == analysis_id)
            .order_by(ThreatSignal.confidence.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_by_org_and_severity(
        self,
        org_id: uuid.UUID,
        severity: ThreatSeverity,
        *,
        limit: int = 50,
    ) -> Sequence[ThreatSignal]:
        """Query threat signals by organization and severity."""
        stmt = (
            select(ThreatSignal)
            .where(ThreatSignal.org_id == org_id)
            .where(ThreatSignal.severity == severity)
            .order_by(ThreatSignal.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_by_attack_type(
        self,
        org_id: uuid.UUID,
        attack_type: AttackType,
        *,
        limit: int = 50,
    ) -> Sequence[ThreatSignal]:
        """Query threats by specific attack vector methodology."""
        stmt = (
            select(ThreatSignal)
            .where(ThreatSignal.org_id == org_id)
            .where(ThreatSignal.attack_type == attack_type)
            .order_by(ThreatSignal.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_by_category(self, org_id: uuid.UUID) -> dict[str, int]:
        """Count findings grouped by threat category."""
        stmt = (
            select(ThreatSignal.category, func.count(ThreatSignal.id))
            .where(ThreatSignal.org_id == org_id)
            .group_by(ThreatSignal.category)
        )
        result = await self.session.execute(stmt)
        return {
            row[0].value if hasattr(row[0], "value") else str(row[0]): row[1]
            for row in result.all()
        }


class ThreatIntelligenceRepository(BaseRepository[ThreatIntelligenceResult]):
    """Data access layer for threat intelligence lookups and cache management."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(ThreatIntelligenceResult, session)

    async def find_active_by_indicator(
        self,
        indicator_type: str,
        indicator_value: str,
    ) -> ThreatIntelligenceResult | None:
        """Find non-expired cached TI result for an indicator."""
        now = datetime.now(UTC)
        stmt = (
            select(ThreatIntelligenceResult)
            .where(ThreatIntelligenceResult.indicator_type == indicator_type.lower())
            .where(ThreatIntelligenceResult.indicator_value == indicator_value.lower())
            .where(
                (ThreatIntelligenceResult.expires_at.is_(None))
                | (ThreatIntelligenceResult.expires_at > now)
            )
            .order_by(ThreatIntelligenceResult.last_checked_at.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()
