"""FastAPI dependency injection factories.

All shared dependencies (DB session, Redis, current user, auth services)
are defined here and injected via FastAPI's Depends() mechanism.

Security dependency chain
--------------------------
get_token_service / get_blocklist_service / get_auth_service
    → get_current_user_claims   (decode & validate JWT)
        → get_current_user      (load User from DB, check active)
            → require_roles     (RBAC gate)
            → require_admin     (convenience alias)
            → ...
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated

import structlog
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.exceptions.domain_exceptions import ForbiddenError, UnauthorizedError
from app.infrastructure.cache.redis_client import RedisCacheAdapter, get_redis_client
from app.infrastructure.config.settings import Settings, get_settings
from app.infrastructure.db.models.enums import UserRoleType
from app.infrastructure.db.models.user import User
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.infrastructure.db.session import AsyncSessionLocal, get_async_session
from app.services.auth_service import AuthService
from app.services.password_service import PasswordService
from app.services.token_blocklist_service import TokenBlocklistService
from app.services.token_service import TokenClaims, TokenService

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# HTTP Bearer scheme (raises 403 automatically on missing header)
# ---------------------------------------------------------------------------
_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Infrastructure dependencies
# ---------------------------------------------------------------------------


async def get_db(session: AsyncSession = Depends(get_async_session)) -> AsyncSession:
    """Yield the async SQLAlchemy session for the current request."""
    return session


async def get_cache() -> AsyncGenerator[RedisCacheAdapter, None]:
    """Yield a Redis cache adapter for the current request."""
    client = await get_redis_client()
    yield RedisCacheAdapter(client)


def get_uow() -> UnitOfWork:
    """Create a fresh UnitOfWork bound to the default session factory."""
    return UnitOfWork(AsyncSessionLocal)


# ---------------------------------------------------------------------------
# Auth service dependencies (singleton-like via lru_cache on Settings)
# ---------------------------------------------------------------------------


def get_token_service(settings: Annotated[Settings, Depends(get_settings)]) -> TokenService:
    """Return a TokenService configured from application settings."""
    return TokenService(settings)


async def get_blocklist_service() -> TokenBlocklistService:
    """Return a TokenBlocklistService backed by the shared Redis client."""
    client = await get_redis_client()
    return TokenBlocklistService(client)


def get_password_service() -> PasswordService:
    """Return a stateless PasswordService instance."""
    return PasswordService()


def get_auth_service(
    token_service: Annotated[TokenService, Depends(get_token_service)],
    blocklist_service: Annotated[TokenBlocklistService, Depends(get_blocklist_service)],
    password_service: Annotated[PasswordService, Depends(get_password_service)],
) -> AuthService:
    """Compose and return the AuthService with all required dependencies."""
    return AuthService(token_service, blocklist_service, password_service)


# ---------------------------------------------------------------------------
# Current user resolution
# ---------------------------------------------------------------------------


async def get_current_user_claims(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
    blocklist_service: Annotated[TokenBlocklistService, Depends(get_blocklist_service)],
) -> TokenClaims:
    """Extract and validate the Bearer JWT from the Authorization header.

    Raises:
        UnauthorizedError: if the token is missing, invalid, expired, or revoked.
    """
    if credentials is None:
        raise UnauthorizedError("Authorization header missing")

    try:
        claims = token_service.decode_token(credentials.credentials, expected_type="access")
    except ValueError as exc:
        raise UnauthorizedError(str(exc)) from exc

    # Check user-level blanket revocation (e.g. after password change)
    revoked_at = await blocklist_service.get_user_revocation_timestamp(claims.user_id)
    if revoked_at is not None:
        from datetime import timedelta

        token_iat = int(
            (claims.exp - timedelta(seconds=token_service.access_ttl_seconds)).timestamp()
        )
        if token_iat < revoked_at:
            raise UnauthorizedError("Token predates a security event. Please log in again.")

    return claims


async def get_optional_user_claims(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
    blocklist_service: Annotated[TokenBlocklistService, Depends(get_blocklist_service)],
) -> TokenClaims | None:
    """Extract and validate JWT if present, returning None if Authorization header is omitted."""
    if credentials is None:
        return None

    try:
        claims = token_service.decode_token(credentials.credentials, expected_type="access")
    except ValueError:
        return None

    revoked_at = await blocklist_service.get_user_revocation_timestamp(claims.user_id)
    if revoked_at is not None:
        from datetime import timedelta

        token_iat = int(
            (claims.exp - timedelta(seconds=token_service.access_ttl_seconds)).timestamp()
        )
        if token_iat < revoked_at:
            return None

    return claims


async def get_current_user(
    claims: Annotated[TokenClaims, Depends(get_current_user_claims)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Load the authenticated User from the database.

    Raises:
        UnauthorizedError: if the user no longer exists or is inactive.
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    stmt = (
        select(User)
        .options(selectinload(User.role), selectinload(User.organization))
        .where(User.id == claims.user_id)
        .where(User.deleted_at.is_(None))
    )
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None:
        raise UnauthorizedError("User account not found")
    if not user.is_active:
        raise UnauthorizedError("User account is disabled")

    return user


# ---------------------------------------------------------------------------
# RBAC authorization dependencies
# ---------------------------------------------------------------------------

# Role hierarchy: VIEWER < USER < SECURITY_ANALYST < ADMIN
_ROLE_LEVEL: dict[str, int] = {
    UserRoleType.VIEWER: 0,
    UserRoleType.USER: 1,
    UserRoleType.SECURITY_ANALYST: 2,
    UserRoleType.ADMIN: 3,
}


def require_roles(*allowed_roles: UserRoleType):  # type: ignore[no-untyped-def]
    """Return a dependency that enforces the caller has one of *allowed_roles*.

    Usage::

        @router.get("/admin-only")
        async def admin_endpoint(
            user: User = Depends(require_roles(UserRoleType.ADMIN))
        ): ...

        @router.get("/analyst-or-admin")
        async def analyst_endpoint(
            user: User = Depends(require_roles(UserRoleType.SECURITY_ANALYST, UserRoleType.ADMIN))
        ): ...
    """

    async def _check(user: Annotated[User, Depends(get_current_user)]) -> User:
        user_role = user.role.role_type if user.role else UserRoleType.VIEWER
        if user_role not in {r.value for r in allowed_roles}:
            raise ForbiddenError(
                f"Requires one of: {[r.value for r in allowed_roles]}. Your role: {user_role}"
            )
        return user

    return _check


def require_min_role(min_role: UserRoleType):  # type: ignore[no-untyped-def]
    """Return a dependency that enforces the caller's role level >= *min_role*.

    Usage::

        @router.get("/analysts-and-above")
        async def endpoint(
            user: User = Depends(require_min_role(UserRoleType.SECURITY_ANALYST))
        ): ...
    """
    min_level = _ROLE_LEVEL[min_role]

    async def _check(user: Annotated[User, Depends(get_current_user)]) -> User:
        user_role = user.role.role_type if user.role else UserRoleType.VIEWER
        user_level = _ROLE_LEVEL.get(user_role, 0)
        if user_level < min_level:
            raise ForbiddenError(f"Requires role level >= '{min_role}'. Your role: '{user_role}'")
        return user

    return _check


# Convenience aliases
require_admin = require_roles(UserRoleType.ADMIN)
require_analyst_or_above = require_min_role(UserRoleType.SECURITY_ANALYST)
require_user_or_above = require_min_role(UserRoleType.USER)


# ---------------------------------------------------------------------------
# Rate limiting dependency
# ---------------------------------------------------------------------------


async def rate_limit_login(request: Request) -> None:
    """Sliding-window rate limit for login endpoint: 10 attempts per IP per minute.

    Uses Redis INCR + EXPIRE for atomic, distributed rate limiting.
    Falls back gracefully if Redis is unavailable (log warning, allow request).
    """
    from app.domain.exceptions.domain_exceptions import RateLimitError

    try:
        redis = await get_redis_client()
        ip = request.client.host if request.client else "unknown"
        key = f"rate_limit:login:{ip}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, 60)  # 1-minute window
        if count > 10:
            logger.warning("rate_limit_exceeded", ip=ip, endpoint="/auth/login")
            raise RateLimitError("Too many login attempts. Please wait before trying again.")
    except RateLimitError:
        raise
    except Exception as exc:
        logger.warning("rate_limit_redis_unavailable", error=str(exc))


async def rate_limit_register(request: Request) -> None:
    """Rate limit registration: 5 per IP per 10 minutes."""
    from app.domain.exceptions.domain_exceptions import RateLimitError

    try:
        redis = await get_redis_client()
        ip = request.client.host if request.client else "unknown"
        key = f"rate_limit:register:{ip}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, 600)  # 10-minute window
        if count > 5:
            logger.warning("rate_limit_exceeded", ip=ip, endpoint="/auth/register")
            raise RateLimitError("Too many registration attempts. Please wait before trying again.")
    except RateLimitError:
        raise
    except Exception as exc:
        logger.warning("rate_limit_redis_unavailable", error=str(exc))
