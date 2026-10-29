"""Pydantic schemas for paginated analysis history queries and responses."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AnalysisHistoryItem(BaseModel):
    """Summarized analysis record tailored for high-density tabular forensic history."""

    analysis_id: str = Field(description="UUID string for the analysis instance")
    email_id: str = Field(description="UUID string for the associated raw email")
    timestamp: datetime = Field(description="Timestamp when email analysis was initiated")
    sender: str = Field(description="Envelope or header from address")
    sender_domain: str = Field(description="Extracted domain of the sender")
    subject: str = Field(default="(No Subject)", description="Email subject line")
    classification: str = Field(description="Security verdict (clean, suspicious, malicious, spam)")
    severity: str = Field(description="Categorical risk tier (critical, high, medium, low, safe)")
    risk_score: int = Field(ge=0, le=100, description="Composite numeric risk score from 0 to 100")
    status: str = Field(
        description="Lifecycle processing state (queued, processing, completed, failed)"
    )
    attack_type: str = Field(default="none", description="Primary attack vector identified")
    duration_ms: int | None = Field(
        default=None, description="Analysis elapsed duration in milliseconds"
    )


class AnalysisHistoryResponse(BaseModel):
    """Server-side paginated analysis history payload with total counts and pagination metadata."""

    items: list[AnalysisHistoryItem] = Field(
        default_factory=list, description="List of forensic history rows"
    )
    total_count: int = Field(ge=0, description="Total matching records across the entire dataset")
    page: int = Field(ge=1, description="Current page number (1-indexed)")
    page_size: int = Field(ge=1, le=100, description="Number of records returned per page")
    total_pages: int = Field(
        ge=1, description="Total number of pages based on total_count and page_size"
    )
    has_next: bool = Field(description="True if subsequent pages of results exist")
    has_prev: bool = Field(description="True if preceding pages of results exist")
