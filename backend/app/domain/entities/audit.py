"""Audit log domain entity."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AuditAction(StrEnum):
    """Type of action recorded in the audit log."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    TRIGGER = "trigger"
    LOGIN = "login"
    LOGOUT = "logout"


class AuditEvent(BaseModel):
    """Immutable audit log entry.

    Once created, audit events are never modified. The audit_log table
    enforces this at the database level.
    """

    model_config = {"frozen": True}

    id: str = Field(description="ULID primary key")
    event_type: str = Field(description="e.g. EMAIL_SUBMITTED, ANALYSIS_COMPLETED")
    actor_user_id: str | None = Field(default=None, description="None for system events")
    actor_ip: str | None = Field(default=None)
    resource_type: str | None = Field(default=None)
    resource_id: str | None = Field(default=None)
    action: AuditAction
    before_state: dict[str, Any] | None = Field(default=None)
    after_state: dict[str, Any] | None = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)
    correlation_id: UUID
    created_at: datetime
