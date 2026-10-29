"""Immutable audit log model for regulatory and security event auditing."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    Enum,
    ForeignKey,
    Index,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.db.models.base_model import BaseModel
from app.infrastructure.db.models.enums import AuditAction

if TYPE_CHECKING:
    from app.infrastructure.db.models.organization import Organization
    from app.infrastructure.db.models.user import User


class AuditLog(BaseModel):
    """Immutable audit trail of user and system security actions."""

    __tablename__ = "audit_logs"

    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Associated organization tenant ID",
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who performed the action (null for system worker)",
    )
    actor_email: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Cached actor email for historical preservation",
    )
    actor_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Client IP address where request originated",
    )
    actor_user_agent: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        comment="HTTP User-Agent header of the requesting client",
    )
    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        default="",
        comment="Specific event identifier e.g. 'EMAIL_SUBMITTED', 'USER_ROLE_CHANGED'",
    )
    resource_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Target resource category (e.g. email, user, analysis, organization)",
    )
    resource_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        comment="Target resource primary key string",
    )
    action: Mapped[AuditAction] = mapped_column(
        Enum(AuditAction, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
        comment="Type of state-changing operation",
    )
    before_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Resource state prior to mutation (for rollback and audit)",
    )
    after_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Resource state following mutation",
    )
    metadata_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="Supplemental request and security headers context",
    )
    correlation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        nullable=False,
        index=True,
        default=uuid.uuid4,
        comment="Trace correlation ID linking related log records",
    )

    # Relationships
    organization: Mapped[Organization | None] = relationship(
        "Organization",
        back_populates="audit_logs",
    )
    actor_user: Mapped[User | None] = relationship(
        "User",
        back_populates="audit_logs",
    )

    __table_args__ = (
        Index("ix_audit_logs_org_created_desc", "org_id", "created_at"),
        Index("ix_audit_logs_actor_created_desc", "actor_user_id", "created_at"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_event_created_desc", "event_type", "created_at"),
    )
