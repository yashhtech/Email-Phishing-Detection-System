"""User management API router (admin operations).

Endpoints
---------
GET    /users            — list users in caller's org (ANALYST+)
GET    /users/{user_id}  — get user by ID (ANALYST+)
PATCH  /users/{user_id}  — update user profile/status (ADMIN only)
DELETE /users/{user_id}  — soft-delete user (ADMIN only)
"""

from __future__ import annotations

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select

from app.api.dependencies import (
    get_uow,
    require_admin,
    require_analyst_or_above,
)
from app.api.schemas.auth import UserResponse
from app.api.schemas.users import UpdateUserRequest, UserListResponse, UserSummary
from app.domain.exceptions.domain_exceptions import ForbiddenError, NotFoundError, ValidationError
from app.infrastructure.db.models.audit import AuditLog
from app.infrastructure.db.models.enums import AuditAction, UserRoleType
from app.infrastructure.db.models.role import Role
from app.infrastructure.db.models.user import User
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])

_ROLE_MAP: dict[str, UserRoleType] = {
    "viewer": UserRoleType.VIEWER,
    "user": UserRoleType.USER,
    "security_analyst": UserRoleType.SECURITY_ANALYST,
    "admin": UserRoleType.ADMIN,
}


def _to_summary(user: User) -> UserSummary:
    data = user.__dict__
    role = data.get("role")
    role_name = role.role_type if role else UserRoleType.VIEWER
    from datetime import UTC, datetime

    return UserSummary(
        id=str(data.get("id", user.id)),
        email=str(data.get("email", user.email)),
        full_name=str(data.get("full_name", user.full_name)),
        role=str(role_name),
        is_active=bool(data.get("is_active", True)),
        org_id=str(data.get("org_id", user.org_id)),
        last_login_at=data.get("last_login_at"),
        created_at=data.get("created_at") or datetime.now(UTC),
    )


def _to_response(user: User) -> UserResponse:
    data = user.__dict__
    role = data.get("role")
    role_name = role.role_type if role else UserRoleType.VIEWER
    from datetime import UTC, datetime

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
# GET /users
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=UserListResponse,
    status_code=status.HTTP_200_OK,
    summary="List users in your organization",
)
async def list_users(
    current_user: Annotated[User, Depends(require_analyst_or_above)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    skip: int = 0,
    limit: int = 50,
    include_inactive: bool = False,
) -> UserListResponse:
    async with uow:
        users = await uow.users.list_by_org(
            current_user.org_id,
            skip=skip,
            limit=limit,
            include_inactive=include_inactive,
        )
        total = await uow.users.count_by_org(current_user.org_id)

    return UserListResponse(
        items=[_to_summary(u) for u in users],
        total=total,
        skip=skip,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# GET /users/{user_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a user by ID",
)
async def get_user(
    user_id: str,
    current_user: Annotated[User, Depends(require_analyst_or_above)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> UserResponse:
    try:
        uid = uuid.UUID(user_id)
    except ValueError as exc:
        raise ValidationError(f"'{user_id}' is not a valid UUID") from exc

    async with uow:
        user = await uow.users.get_by_id(uid)

    if user is None:
        raise NotFoundError("User", user_id)

    # Analysts can only view users in their own org
    if user.org_id != current_user.org_id:
        raise ForbiddenError("Cannot access users from a different organization")

    return _to_response(user)


# ---------------------------------------------------------------------------
# PATCH /users/{user_id}
# ---------------------------------------------------------------------------


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update user profile or status (admin only)",
)
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_admin)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> UserResponse:
    try:
        uid = uuid.UUID(user_id)
    except ValueError as exc:
        raise ValidationError(f"'{user_id}' is not a valid UUID") from exc

    # Prevent self-demotion
    if uid == current_user.id and body.role_type is not None:
        if body.role_type != "admin":
            raise ForbiddenError("Admins cannot change their own role")

    ip = request.client.host if request.client else None
    ua = request.headers.get("User-Agent")

    async with uow:
        user = await uow.users.get_by_id(uid)
        if user is None:
            raise NotFoundError("User", user_id)
        if user.org_id != current_user.org_id:
            raise ForbiddenError("Cannot modify users from a different organization")

        before_state = {
            "full_name": user.full_name,
            "is_active": user.is_active,
        }

        if body.full_name is not None:
            user.full_name = body.full_name
        if body.is_active is not None:
            user.is_active = body.is_active
        if body.role_type is not None:
            role_type = _ROLE_MAP[body.role_type]
            role_result = await uow.session.execute(  # type: ignore[union-attr]
                select(Role).where(Role.role_type == role_type)
            )
            new_role = role_result.scalar_one_or_none()
            if new_role is None:
                raise ValidationError(f"No role found for type '{body.role_type}'")
            user.role_id = new_role.id

        await uow.users.update(user)

        await uow.audit_logs.create(
            AuditLog(
                org_id=current_user.org_id,
                action=AuditAction.UPDATE,
                actor_user_id=current_user.id,
                actor_ip=ip,
                actor_user_agent=ua,
                resource_type="user",
                resource_id=user_id,
                before_state=before_state,
                after_state={
                    "full_name": user.full_name,
                    "is_active": user.is_active,
                },
            )
        )

    return _to_response(user)


# ---------------------------------------------------------------------------
# DELETE /users/{user_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete a user (admin only)",
)
async def delete_user(
    user_id: str,
    request: Request,
    current_user: Annotated[User, Depends(require_admin)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> None:
    try:
        uid = uuid.UUID(user_id)
    except ValueError as exc:
        raise ValidationError(f"'{user_id}' is not a valid UUID") from exc

    if uid == current_user.id:
        raise ForbiddenError("Cannot delete your own account")

    ip = request.client.host if request.client else None
    ua = request.headers.get("User-Agent")

    async with uow:
        user = await uow.users.get_by_id(uid)
        if user is None:
            raise NotFoundError("User", user_id)
        if user.org_id != current_user.org_id:
            raise ForbiddenError("Cannot delete users from a different organization")

        deleted = await uow.users.delete(uid, soft=True)
        if not deleted:
            raise NotFoundError("User", user_id)

        await uow.audit_logs.create(
            AuditLog(
                org_id=current_user.org_id,
                action=AuditAction.DELETE,
                actor_user_id=current_user.id,
                actor_ip=ip,
                actor_user_agent=ua,
                resource_type="user",
                resource_id=user_id,
                before_state={"email": user.email, "is_active": user.is_active},
                after_state={"deleted": True},
            )
        )
