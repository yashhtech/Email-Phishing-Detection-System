"""System metrics and telemetry model for real persisted monitoring."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.db.models.base_model import BaseModel
from app.infrastructure.db.models.enums import MetricType


class SystemMetric(BaseModel):
    """Real persisted platform metrics and time-series telemetry."""

    __tablename__ = "system_metrics"

    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="Associated organization tenant ID (null for platform-wide)",
    )
    metric_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Metric identifier e.g. 'emails_processed_total', 'avg_risk_score'",
    )
    metric_type: Mapped[MetricType] = mapped_column(
        Enum(MetricType, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        default=MetricType.GAUGE,
        nullable=False,
        index=True,
        comment="Type of metric (counter, gauge, histogram)",
    )
    value: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Numeric metric sample value",
    )
    unit: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
        comment="Measurement unit (ms, count, percent, score)",
    )
    labels: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="Dimensional tags e.g. {'verdict': 'malicious', 'model': 'v2.3'}",
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Timestamp when metric point was captured",
    )

    __table_args__ = (
        Index("ix_system_metrics_name_recorded", "metric_name", "recorded_at"),
        Index("ix_system_metrics_org_name_recorded", "org_id", "metric_name", "recorded_at"),
    )
