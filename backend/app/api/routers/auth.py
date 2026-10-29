"""Authentication API router.

Endpoints
---------
POST /auth/login         — password login → token pair
POST /auth/register      — new user registration
POST /auth/refresh       — rotate refresh token → fresh token pair
POST /auth/logout        — revoke refresh token
GET  /auth/me            — current user profile
POST /auth/me/password   — change own password

All endpoints return structured JSON. Passwords are never echoed back.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Request, status

from app.api.dependencies import (
    get_auth_service,
    get_current_user,
    get_uow,
    rate_limit_login,
    rate_limit_register,
)
from app.api.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.domain.exceptions.domain_exceptions import ValidationError
from app.infrastructure.db.models.enums import UserRoleType
from app.infrastructure.db.models.user import User
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.services.auth_service import AuthService

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _user_response(user: User) -> UserResponse:
    """Build a UserResponse safely without triggering lazy-load on detached instances."""
    data = user.__dict__
    role = data.get("role")
    role_name = role.role_type if role else UserRoleType.VIEWER
    return UserResponse(
        id=str(data.get("id", user.id)),
        email=str(data.get("email", user.email)),
        full_name=str(data.get("full_name", user.full_name)),
        role=str(role_name),
        is_active=bool(data.get("is_active", True)),
        org_id=str(data.get("org_id", user.org_id)),
        last_login_at=data.get("last_login_at"),
        created_at=data.get("created_at") or datetime.now(UTC),
        updated_at=data.get("updated_at") or datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Login with email and password",
    description=(
        "Authenticate with email and password. Returns a short-lived access token "
        "and a longer-lived refresh token. The access token should be sent as a "
        "Bearer token in the Authorization header."
    ),
)
async def login(
    body: LoginRequest,
    request: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    _rate_limit: Annotated[None, Depends(rate_limit_login)],
) -> TokenResponse:
    ip = request.client.host if request.client else None
    ua = request.headers.get("User-Agent")

    token_pair = await auth_service.login(
        body.email,
        body.password,
        uow,
        ip_address=ip,
        user_agent=ua,
    )
    user_resp = (
        UserResponse(**token_pair.user_data)
        if token_pair.user_data
        else _user_response(token_pair.user)
    )
    return TokenResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        access_expires_at=token_pair.access_expires_at,
        refresh_expires_at=token_pair.refresh_expires_at,
        user=user_resp,
    )


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description=(
        "Create a new user account within an organization. "
        "The caller must supply a valid org_id. "
        "Password must be at least 8 characters with mixed case, digit, and special character."
    ),
)
async def register(
    body: RegisterRequest,
    request: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    _rate_limit: Annotated[None, Depends(rate_limit_register)],
) -> UserResponse:
    ip = request.client.host if request.client else None
    ua = request.headers.get("User-Agent")

    try:
        org_id = uuid.UUID(body.org_id)
    except ValueError as exc:
        raise ValidationError("org_id must be a valid UUID") from exc

    user = await auth_service.register(
        body.email,
        body.password,
        body.full_name,
        uow,
        org_id=org_id,
        role_type=UserRoleType.USER,
        ip_address=ip,
        user_agent=ua,
    )
    return _user_response(user)


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description=(
        "Exchange a valid refresh token for a new access/refresh token pair. "
        "The old refresh token is immediately revoked (rotation strategy)."
    ),
)
async def refresh_token(
    body: RefreshRequest,
    request: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> TokenResponse:
    ip = request.client.host if request.client else None
    ua = request.headers.get("User-Agent")

    token_pair = await auth_service.refresh(
        body.refresh_token,
        uow,
        ip_address=ip,
        user_agent=ua,
    )
    user_resp = (
        UserResponse(**token_pair.user_data)
        if token_pair.user_data
        else _user_response(token_pair.user)
    )
    return TokenResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        access_expires_at=token_pair.access_expires_at,
        refresh_expires_at=token_pair.refresh_expires_at,
        user=user_resp,
    )


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------


@router.post(
    "/logout",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout and revoke refresh token",
    description="Revoke the supplied refresh token. Idempotent — safe to call multiple times.",
)
async def logout(
    body: LogoutRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> MessageResponse:
    ip = request.client.host if request.client else None
    ua = request.headers.get("User-Agent")

    await auth_service.logout(
        body.refresh_token,
        uow,
        current_user.id,
        ip_address=ip,
        user_agent=ua,
    )
    return MessageResponse(message="Successfully logged out")


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user profile",
    description="Return the authenticated user's profile. Requires a valid access token.",
)
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UserResponse:
    return _user_response(current_user)


# ---------------------------------------------------------------------------
# POST /auth/me/password
# ---------------------------------------------------------------------------


@router.post(
    "/me/password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Change own password",
    description=(
        "Change the authenticated user's password. "
        "All existing refresh tokens for this user are revoked on success."
    ),
)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> MessageResponse:
    ip = request.client.host if request.client else None
    ua = request.headers.get("User-Agent")

    await auth_service.change_password(
        current_user.id,
        body.current_password,
        body.new_password,
        uow,
        ip_address=ip,
        user_agent=ua,
    )
    return MessageResponse(
        message="Password changed successfully. Please log in again with your new password."
    )
