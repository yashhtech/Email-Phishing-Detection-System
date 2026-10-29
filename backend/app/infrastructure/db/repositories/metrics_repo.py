"""Repository for real persisted SystemMetrics and telemetry."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.models.enums import MetricType
from app.infrastructure.db.models.metrics import SystemMetric
from app.infrastructure.db.repositories.base import BaseRepository


class SystemMetricRepository(BaseRepository[SystemMetric]):
    """Data access layer for platform metrics."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SystemMetric, session)

    async def record(
        self,
        *,
        metric_name: str,
        value: float,
        metric_type: MetricType = MetricType.GAUGE,
        unit: str | None = None,
        org_id: uuid.UUID | None = None,
        labels: dict[str, Any] | None = None,
        recorded_at: datetime | None = None,
    ) -> SystemMetric:
        """Capture and persist a metric sample."""
        metric = SystemMetric(
            metric_name=metric_name,
            metric_type=metric_type,
            value=value,
            unit=unit,
            org_id=org_id,
            labels=labels or {},
            recorded_at=recorded_at or datetime.now(UTC),
        )
        return await self.create(metric)

    async def get_time_series(
        self,
        metric_name: str,
        *,
        org_id: uuid.UUID | None = None,
        start_time: datetime,
        end_time: datetime,
    ) -> Sequence[SystemMetric]:
        """Fetch time-series samples within a window."""
        stmt = (
            select(SystemMetric)
            .where(SystemMetric.metric_name == metric_name)
            .where(SystemMetric.recorded_at >= start_time)
            .where(SystemMetric.recorded_at <= end_time)
        )
        if org_id is not None:
            stmt = stmt.where(SystemMetric.org_id == org_id)

        stmt = stmt.order_by(SystemMetric.recorded_at.asc())
        result = await self.session.execute(stmt)
        return result.scalars().all()
