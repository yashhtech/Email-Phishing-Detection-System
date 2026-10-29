"""Schemas and contracts for asynchronous analysis job execution.

Defines:
- JobStatus: Lifecycle states (queued, processing, completed, failed)
- AnalysisStage: Fine-grained pipeline execution stages for live WebSocket progress
- AnalysisJob: Encapsulated job payload dispatched to background workers
- WorkerHealthStatus: Real-time worker telemetry and health metrics
- AnalysisSubmitResult: Immediate response returned by POST /analysis (<20ms)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class JobStatus(StrEnum):
    """Lifecycle states of an asynchronous analysis job."""

    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class AnalysisStage(StrEnum):
    """Sequential pipeline stages reported over WebSocket."""

    QUEUED = "queued"
    PREPROCESSING = "preprocessing"
    SECURITY_ENGINE = "security_engine"
    ML_ENGINE = "ml_engine"
    THREAT_INTEL = "threat_intel"
    GROQ_LLM = "groq_llm"
    RISK_ENGINE = "risk_engine"
    PERSISTENCE = "persistence"
    COMPLETED = "completed"
    FAILED = "failed"


class AnalysisJob(BaseModel):
    """Background work item passed to analysis pipeline workers."""

    model_config = ConfigDict(frozen=True)

    job_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this worker job execution",
    )
    analysis_id: uuid.UUID = Field(
        description="Authoritative database Analysis record ID",
    )
    email_id: uuid.UUID = Field(
        description="Associated database Email record ID",
    )
    org_id: uuid.UUID = Field(
        description="Tenant organization ID",
    )
    attempt: int = Field(
        default=1,
        ge=1,
        description="Current attempt count (1 for initial run, >1 for retries)",
    )
    max_retries: int = Field(
        default=3,
        ge=0,
        description="Maximum retry attempts on transient pipeline errors",
    )
    enqueued_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when job was placed in queue",
    )
    raw_content: str | None = Field(
        default=None,
        description="Optional raw RFC 822 / .eml text for pipeline ingestion",
    )


class WorkerHealthStatus(BaseModel):
    """Health check metrics and operational telemetry for analysis workers."""

    model_config = ConfigDict(frozen=True)

    status: str = Field(
        description="'healthy', 'degraded', or 'stopped'",
    )
    active_workers: int = Field(
        ge=0,
        description="Count of currently active worker worker threads/tasks",
    )
    active_jobs: int = Field(
        ge=0,
        description="Count of jobs currently in 'processing' state",
    )
    completed_jobs: int = Field(
        ge=0,
        description="Total cumulative count of successfully completed jobs",
    )
    failed_jobs: int = Field(
        ge=0,
        description="Total cumulative count of failed jobs",
    )
    queue_depth: int = Field(
        ge=0,
        description="Number of jobs currently pending in queue",
    )
    uptime_seconds: float = Field(
        ge=0.0,
        description="Elapsed uptime since worker pool startup",
    )
    last_heartbeat: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of most recent worker heartbeat",
    )


class AnalysisSubmitResult(BaseModel):
    """Immediate non-blocking response returned to client upon job dispatch (<20ms)."""

    model_config = ConfigDict(frozen=True)

    analysis_id: uuid.UUID = Field(description="Unique ID for querying analysis status")
    email_id: uuid.UUID = Field(description="Database Email ID")
    status: JobStatus = Field(default=JobStatus.QUEUED, description="Initial job status")
    created_at: datetime = Field(description="Timestamp when analysis was accepted")
    tracking_url: str = Field(description="GET endpoint to poll for status and final results")
    websocket_url: str = Field(description="WebSocket endpoint to stream live stage updates")
