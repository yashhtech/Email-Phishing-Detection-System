"""Pydantic schemas for authentication API endpoints.

All response schemas explicitly exclude password fields.
Request schemas validate and sanitize input before it reaches the service layer.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """Credentials for password-based authentication."""

    email: EmailStr = Field(description="User email address")
    password: str = Field(min_length=1, description="User password")

    @field_validator("email", mode="before")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.lower().strip()


class RegisterRequest(BaseModel):
    """New user registration payload."""

    email: EmailStr = Field(description="User email address")
    password: str = Field(
        min_length=8,
        max_length=128,
        description="Password (min 8 chars, must include upper, lower, digit, special)",
    )
    full_name: str = Field(
        min_length=2,
        max_length=255,
        description="User's full display name",
    )
    org_id: str = Field(description="Target organization UUID")

    @field_validator("email", mode="before")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.lower().strip()

    @field_validator("full_name", mode="before")
    @classmethod
    def strip_name(cls, v: str) -> str:
        return v.strip()


class RefreshRequest(BaseModel):
    """Refresh token rotation request."""

    refresh_token: str = Field(description="Current refresh token")


class LogoutRequest(BaseModel):
    """Logout request carries the refresh token to revoke."""

    refresh_token: str = Field(description="Refresh token to revoke")


class ChangePasswordRequest(BaseModel):
    """Authenticated password change."""

    current_password: str = Field(description="Existing password")
    new_password: str = Field(
        min_length=8,
        max_length=128,
        description="New password",
    )


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class UserResponse(BaseModel):
    """Public representation of a user — never includes the password hash."""

    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    org_id: str
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    """Token pair returned after successful login or refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    access_expires_at: datetime
    refresh_expires_at: datetime
    user: UserResponse


class MessageResponse(BaseModel):
    """Generic success message."""

    message: str
    success: bool = True
