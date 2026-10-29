"""Analysis domain entities."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalysisStatus(StrEnum):
    """Status of an analysis job."""

    QUEUED = "queued"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"
    SKIPPED = "skipped"


class RiskLevel(StrEnum):
    """Composite risk classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class AnalysisResult(BaseModel):
    """Result of a full email analysis pipeline."""

    model_config = {"frozen": True}

    id: str = Field(description="ULID primary key")
    email_id: str
    status: AnalysisStatus = Field(default=AnalysisStatus.QUEUED)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    duration_ms: int | None = Field(default=None)
    risk_score: int | None = Field(default=None, ge=0, le=100)
    risk_level: RiskLevel | None = Field(default=None)
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)
    error_message: str | None = Field(default=None)
    retry_count: int = Field(default=0, ge=0)
