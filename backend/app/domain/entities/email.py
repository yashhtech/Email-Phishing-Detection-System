"""Email domain entity."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class EmailStatus(StrEnum):
    """Lifecycle status of a submitted email."""

    QUEUED = "queued"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"


class EmailPriority(StrEnum):
    """Analysis priority level."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class Email(BaseModel):
    """Core email domain entity.

    Represents an email submitted for threat analysis. This is a pure
    domain object with no framework dependencies.
    """

    model_config = {"frozen": True}

    id: str = Field(description="ULID primary key")
    message_id: str = Field(description="RFC 5322 Message-ID header value")
    subject: str | None = Field(default=None)
    from_address: str = Field(description="Sender email address")
    from_domain: str = Field(description="Sender domain, extracted from from_address")
    to_addresses: list[str] = Field(default_factory=list)
    reply_to: str | None = Field(default=None)
    received_at: datetime = Field(description="Original email date from headers")
    body_preview: str | None = Field(default=None, max_length=500)
    has_attachments: bool = Field(default=False)
    attachment_count: int = Field(default=0, ge=0)
    source: str = Field(default="api")
    priority: EmailPriority = Field(default=EmailPriority.NORMAL)
    status: EmailStatus = Field(default=EmailStatus.QUEUED)
    raw_eml_path: str | None = Field(default=None)
    submitted_by_user_id: str | None = Field(default=None)
