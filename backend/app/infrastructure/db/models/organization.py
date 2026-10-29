"""Organization multi-tenancy model."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Boolean, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.db.models.base_model import BaseModel, SoftDeleteMixin

if TYPE_CHECKING:
    from app.infrastructure.db.models.analysis import Analysis
    from app.infrastructure.db.models.audit import AuditLog
    from app.infrastructure.db.models.email import Email
    from app.infrastructure.db.models.user import User


class Organization(BaseModel, SoftDeleteMixin):
    """Multi-tenant organization account."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Organization display name",
    )
    slug: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique URL/tenant identifier",
    )
    primary_domain: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="Primary domain of the organization",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
        comment="Account active status",
    )
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="Tenant-specific configuration and threshold overrides",
    )

    # Relationships
    users: Mapped[list[User]] = relationship(
        "User",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    emails: Mapped[list[Email]] = relationship(
        "Email",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    analyses: Mapped[list[Analysis]] = relationship(
        "Analysis",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        "AuditLog",
        back_populates="organization",
    )

    __table_args__ = (Index("ix_organizations_active_slug", "is_active", "slug"),)
