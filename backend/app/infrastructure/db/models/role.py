"""Role model for fine-grained role-based access control (RBAC)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, Enum, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.db.models.base_model import BaseModel
from app.infrastructure.db.models.enums import UserRoleType

if TYPE_CHECKING:
    from app.infrastructure.db.models.user import User


class Role(BaseModel):
    """Platform access control role."""

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique role name e.g. 'Security Analyst'",
    )
    role_type: Mapped[UserRoleType] = mapped_column(
        Enum(UserRoleType, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=UserRoleType.VIEWER,
        index=True,
        comment="Base system role level",
    )
    description: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Human-readable role description",
    )
    permissions: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="List of granular permission codes",
    )
    is_system_role: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="System-defined roles cannot be deleted",
    )

    # Relationships
    users: Mapped[list[User]] = relationship(
        "User",
        back_populates="role",
    )

    __table_args__ = (Index("ix_roles_role_type_name", "role_type", "name"),)
