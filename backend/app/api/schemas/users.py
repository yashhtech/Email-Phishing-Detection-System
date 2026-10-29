"""Pydantic schemas for user management API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class UpdateUserRequest(BaseModel):
    """Admin: update an existing user's profile / status."""

    full_name: str | None = Field(default=None, min_length=2, max_length=255)
    is_active: bool | None = Field(default=None)
    role_type: Literal["viewer", "user", "security_analyst", "admin"] | None = Field(default=None)

    @field_validator("full_name", mode="before")
    @classmethod
    def strip_name(cls, v: str | None) -> str | None:
        return v.strip() if v else v


class UserListResponse(BaseModel):
    """Paginated list of users."""

    items: list[UserSummary]
    total: int
    skip: int
    limit: int


class UserSummary(BaseModel):
    """Compact user summary for list views."""

    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    org_id: str
    last_login_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}
