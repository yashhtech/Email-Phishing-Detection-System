"""Authentication application service.

Orchestrates the login, registration, token-refresh, and logout flows.
Does NOT contain raw SQL — all DB access goes through the UnitOfWork /
repository pattern.

Security invariants enforced here
----------------------------------
1. Passwords are never returned in any response DTO.
2. Failed logins are rate-limited via an exponential back-off counter.
3. After MAX_FAILED_ATTEMPTS the account is locked for LOCKOUT_MINUTES.
4. Successful login resets the counter and records last_login_at.
5. Refresh tokens are rotated on every use (old JTI revoked immediately).
6. Logout revokes the refresh token JTI in Redis.
7. Password changes revoke all existing tokens for the user.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.domain.exceptions.domain_exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
    ValidationError,
)
from app.infrastructure.db.models.audit import AuditLog
from app.infrastructure.db.models.enums import AuditAction, UserRoleType
from app.infrastructure.db.models.user import User
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.services.password_service import PasswordService
from app.services.token_blocklist_service import TokenBlocklistService
from app.services.token_service import TokenClaims, TokenService

logger = structlog.get_logger(__name__)

# Account lockout policy
MAX_FAILED_ATTEMPTS: int = 5
LOCKOUT_MINUTES: int = 15


class AuthTokenPair:
    """Value object returned after a successful authentication event."""

    __slots__ = (
        "access_expires_at",
        "access_token",
        "refresh_expires_at",
        "refresh_token",
        "user",
        "user_data",
    )

    def __init__(
        self,
        access_token: str,
        refresh_token: str,
        access_expires_at: datetime,
        refresh_expires_at: datetime,
        user: User,
        user_data: dict[str, Any] | None = None,
    ) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.access_expires_at = access_expires_at
        self.refresh_expires_at = refresh_expires_at
        self.user = user
        self.user_data = user_data or {}


class AuthService:
    """Orchestrates authentication flows using injected infrastructure services."""

    def __init__(
        self,
        token_service: TokenService,
        blocklist_service: TokenBlocklistService,
        password_service: PasswordService,
    ) -> None:
        self._tokens = token_service
        self._blocklist = blocklist_service
        self._passwords = password_service

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    async def login(
        self,
        email: str,
        plain_password: str,
        uow: UnitOfWork,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> AuthTokenPair:
        """Authenticate *email* / *password* and return a fresh token pair."""
        email = email.lower().strip()

        async with uow:
            user = await uow.users.get_by_email(email, include_deleted=False)

            if user is None:
                # Don't reveal whether the email exists
                logger.warning("login_unknown_email", email=email, ip=ip_address)
                raise UnauthorizedError("Invalid credentials")

            # Lockout check (handles both tz-aware and tz-naive SQLite datetimes)
            if user.locked_until is not None:
                locked_until = user.locked_until
                if locked_until.tzinfo is None:
                    locked_until = locked_until.replace(tzinfo=UTC)
                now_utc = datetime.now(UTC)
                if locked_until > now_utc:
                    remaining = int((locked_until - now_utc).total_seconds())
                    logger.warning(
                        "login_account_locked",
                        user_id=str(user.id),
                        unlock_in_seconds=remaining,
                    )
                    raise RateLimitError(
                        f"Account locked due to too many failed attempts. "
                        f"Try again in {remaining // 60 + 1} minutes."
                    )

            if not user.is_active:
                raise ForbiddenError("Account is disabled")

            # Password verification
            if not self._passwords.verify_password(plain_password, user.hashed_password):
                lock_until = (
                    datetime.now(UTC) + timedelta(minutes=LOCKOUT_MINUTES)
                    if user.failed_login_attempts + 1 >= MAX_FAILED_ATTEMPTS
                    else None
                )
                attempts = await uow.users.increment_failed_login(user.id, lock_until=lock_until)
                await uow.audit_logs.create(
                    self._make_audit(
                        AuditAction.FAILED_LOGIN,
                        user.id,
                        user.org_id,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        detail={"attempts": attempts},
                    )
                )
                # Commit the failure counter BEFORE raising so it is persisted
                await uow.commit()

                if attempts >= MAX_FAILED_ATTEMPTS:
                    logger.warning(
                        "login_account_locked_now",
                        user_id=str(user.id),
                        attempts=attempts,
                    )
                    raise RateLimitError(
                        f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes."
                    )
                raise UnauthorizedError("Invalid credentials")

            # Success — reset counters and record login
            await uow.users.record_login(user.id)

            # Opportunistic rehash if hash parameters have been upgraded
            if self._passwords.needs_rehash(user.hashed_password):
                user.hashed_password = self._passwords.hash_password(plain_password)

            token_pair = self._issue_token_pair(user)

            await uow.audit_logs.create(
                self._make_audit(
                    AuditAction.LOGIN,
                    user.id,
                    user.org_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
            )

        logger.info("login_success", user_id=str(user.id), email=email)
        return token_pair

    # ------------------------------------------------------------------
    # Register
    # ------------------------------------------------------------------

    async def register(
        self,
        email: str,
        plain_password: str,
        full_name: str,
        uow: UnitOfWork,
        *,
        org_id: uuid.UUID,
        role_type: UserRoleType = UserRoleType.USER,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> User:
        """Create a new user account within *org_id*.

        Password strength is validated here before hashing.
        Returns the persisted User (without password hash exposed).
        """
        email = email.lower().strip()
        self._validate_password_strength(plain_password)

        from sqlalchemy import select

        from app.infrastructure.db.models.role import Role

        async with uow:
            # Check email uniqueness
            existing = await uow.users.get_by_email(email, include_deleted=True)
            if existing is not None:
                raise ConflictError(f"An account with email '{email}' already exists")

            # Verify org exists
            org = await uow.organizations.get_by_id(org_id)
            if org is None:
                raise NotFoundError("Organization", str(org_id))

            # Find matching system role
            db_role_result = await uow.session.execute(  # type: ignore[union-attr]
                select(Role).where(Role.role_type == role_type)
            )
            db_role_obj = db_role_result.scalar_one_or_none()
            if db_role_obj is None:
                raise ValidationError(f"No system role found for type '{role_type}'")

            hashed = self._passwords.hash_password(plain_password)
            new_user = User(
                org_id=org_id,
                role_id=db_role_obj.id,
                email=email,
                full_name=full_name.strip(),
                hashed_password=hashed,
                is_active=True,
                failed_login_attempts=0,
            )
            await uow.users.create(new_user)

            await uow.audit_logs.create(
                self._make_audit(
                    AuditAction.CREATE,
                    new_user.id,
                    org_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    detail={"resource": "user", "email": email},
                )
            )

        logger.info("user_registered", user_id=str(new_user.id), email=email)
        return new_user

    # ------------------------------------------------------------------
    # Token refresh
    # ------------------------------------------------------------------

    async def refresh(
        self,
        refresh_token: str,
        uow: UnitOfWork,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> AuthTokenPair:
        """Rotate the refresh token and issue a fresh token pair."""
        try:
            claims: TokenClaims = self._tokens.decode_token(refresh_token, expected_type="refresh")
        except ValueError as exc:
            raise UnauthorizedError(str(exc)) from exc

        if await self._blocklist.is_revoked(claims.jti):
            logger.warning("refresh_token_revoked", jti=str(claims.jti))
            raise UnauthorizedError("Refresh token has been revoked")

        # Revoke old refresh token immediately (rotation)
        remaining_ttl = max(
            0,
            int((claims.exp - datetime.now(UTC)).total_seconds()),
        )
        await self._blocklist.revoke(claims.jti, remaining_ttl or 1)

        async with uow:
            user = await uow.users.get_by_id(claims.user_id)
            if user is None or not user.is_active:
                raise UnauthorizedError("User account not found or disabled")

            # Check user-level revocation (e.g. password changed after token issue)
            revoked_at = await self._blocklist.get_user_revocation_timestamp(claims.user_id)
            token_iat = int(
                (claims.exp - timedelta(seconds=self._tokens.refresh_ttl_seconds)).timestamp()
            )
            if revoked_at is not None and token_iat < revoked_at:
                raise UnauthorizedError("Token predates a security event. Please log in again.")

            token_pair = self._issue_token_pair(user)

            await uow.audit_logs.create(
                self._make_audit(
                    AuditAction.TOKEN_REFRESH,
                    user.id,
                    user.org_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
            )

        return token_pair

    # ------------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------------

    async def logout(
        self,
        refresh_token: str,
        uow: UnitOfWork,
        current_user_id: uuid.UUID,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Revoke the user's refresh token.

        Silently succeeds even if the token is already revoked (idempotent).
        """
        try:
            claims = self._tokens.decode_token(refresh_token, expected_type="refresh")
        except ValueError:
            # Don't error on malformed token during logout — just no-op
            return

        remaining_ttl = max(0, int((claims.exp - datetime.now(UTC)).total_seconds()))
        await self._blocklist.revoke(claims.jti, remaining_ttl or 1)

        async with uow:
            user = await uow.users.get_by_id(current_user_id)
            org_id = user.org_id if user else uuid.UUID(int=0)
            await uow.audit_logs.create(
                self._make_audit(
                    AuditAction.LOGOUT,
                    current_user_id,
                    org_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
            )

        logger.info("logout_success", user_id=str(current_user_id))

    # ------------------------------------------------------------------
    # Change password
    # ------------------------------------------------------------------

    async def change_password(
        self,
        user_id: uuid.UUID,
        current_password: str,
        new_password: str,
        uow: UnitOfWork,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Verify current password, set new hash, revoke all existing tokens."""
        self._validate_password_strength(new_password)

        async with uow:
            user = await uow.users.get_by_id(user_id)
            if user is None:
                raise NotFoundError("User", str(user_id))

            if not self._passwords.verify_password(current_password, user.hashed_password):
                raise UnauthorizedError("Current password is incorrect")

            user.hashed_password = self._passwords.hash_password(new_password)
            await uow.session.flush()  # type: ignore[union-attr]

            # Revoke all tokens for this user
            await self._blocklist.revoke_all_for_user(
                user_id, ttl_seconds=self._tokens.refresh_ttl_seconds
            )

            await uow.audit_logs.create(
                self._make_audit(
                    AuditAction.PASSWORD_CHANGE,
                    user_id,
                    user.org_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
            )

        logger.info("password_changed", user_id=str(user_id))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _issue_token_pair(self, user: User) -> AuthTokenPair:
        ud = user.__dict__
        role = ud.get("role")
        role_val = role.role_type if role else UserRoleType.VIEWER

        access_token, _a_jti, access_exp = self._tokens.create_access_token(
            user_id=user.id,
            role=role_val,
            org_id=user.org_id,
        )
        refresh_token, _r_jti, refresh_exp = self._tokens.create_refresh_token(
            user_id=user.id,
            role=role_val,
            org_id=user.org_id,
        )
        created = ud.get("created_at") or datetime.now(UTC)
        updated = ud.get("updated_at") or created
        user_data = {
            "id": str(user.id),
            "email": str(ud.get("email", user.email)),
            "full_name": str(ud.get("full_name", user.full_name)),
            "role": str(role_val),
            "is_active": bool(ud.get("is_active", True)),
            "org_id": str(user.org_id),
            "last_login_at": ud.get("last_login_at"),
            "created_at": created,
            "updated_at": updated,
        }
        return AuthTokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_at=access_exp,
            refresh_expires_at=refresh_exp,
            user=user,
            user_data=user_data,
        )

    @staticmethod
    def _validate_password_strength(password: str) -> None:
        """Enforce minimum password requirements.

        Rules:
          - At least 8 characters
          - At least one uppercase letter
          - At least one lowercase letter
          - At least one digit
          - At least one special character
        """
        errors: list[str] = []
        if len(password) < 8:
            errors.append("at least 8 characters")
        if not any(c.isupper() for c in password):
            errors.append("at least one uppercase letter")
        if not any(c.islower() for c in password):
            errors.append("at least one lowercase letter")
        if not any(c.isdigit() for c in password):
            errors.append("at least one digit")
        if not any(c in r"!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
            errors.append("at least one special character (!@#$%^&*...)")
        if errors:
            raise ValidationError("Password must contain: " + ", ".join(errors))

    @staticmethod
    def _make_audit(
        action: AuditAction,
        user_id: uuid.UUID,
        org_id: uuid.UUID,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
        detail: dict | None = None,  # type: ignore[type-arg]
    ) -> AuditLog:
        return AuditLog(
            org_id=org_id,
            action=action,
            actor_user_id=user_id,
            actor_ip=ip_address,
            actor_user_agent=user_agent,
            resource_type="auth",
            resource_id=str(user_id),
            after_state=detail or {},
        )
