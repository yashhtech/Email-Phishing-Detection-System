"""User domain entity."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, EmailStr, Field


class UserRole(StrEnum):
    """User access role."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


class User(BaseModel):
    """User domain entity."""

    model_config = {"frozen": True}

    id: str = Field(description="ULID primary key")
    email: EmailStr
    full_name: str
    role: UserRole = Field(default=UserRole.VIEWER)
    is_active: bool = Field(default=True)
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = Field(default=None)
