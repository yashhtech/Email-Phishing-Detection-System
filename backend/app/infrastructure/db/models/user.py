"""User authentication and authorization model."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.db.models.base_model import BaseModel, SoftDeleteMixin

if TYPE_CHECKING:
    from app.infrastructure.db.models.audit import AuditLog
    from app.infrastructure.db.models.email import Email
    from app.infrastructure.db.models.organization import Organization
    from app.infrastructure.db.models.role import Role


class User(BaseModel, SoftDeleteMixin):
    """User account entity within an organization."""

    __tablename__ = "users"

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Associated organization tenant ID",
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Assigned security role ID",
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="User email address (login identifier)",
    )
    full_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="User legal / display name",
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Argon2id salted password hash",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
        comment="Account active / enabled status",
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of most recent successful login",
    )
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Consecutive failed authentication attempts",
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Account lockout expiration timestamp if brute-force detected",
    )

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="users",
        lazy="selectin",
    )
    role: Mapped[Role] = relationship(
        "Role",
        back_populates="users",
        lazy="selectin",
    )
    submitted_emails: Mapped[list[Email]] = relationship(
        "Email",
        back_populates="submitted_by_user",
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        "AuditLog",
        back_populates="actor_user",
    )

    __table_args__ = (
        Index("ix_users_org_active", "org_id", "is_active"),
        Index("ix_users_org_email", "org_id", "email"),
        Index("ix_users_role_org", "role_id", "org_id"),
    )
