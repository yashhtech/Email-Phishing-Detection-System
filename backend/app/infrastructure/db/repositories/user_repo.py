"""Repository for User accounts and authentication state."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.infrastructure.db.models.user import User
from app.infrastructure.db.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    """Data access layer for User accounts."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(User, session)

    async def get_by_id(
        self,
        entity_id: uuid.UUID,
        *,
        include_deleted: bool = False,
    ) -> User | None:
        """Fetch user by primary key with role and organization preloaded."""
        stmt = (
            select(User)
            .options(selectinload(User.organization), selectinload(User.role))
            .where(User.id == entity_id)
        )
        if not include_deleted:
            stmt = stmt.where(User.deleted_at.is_(None))
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str, *, include_deleted: bool = False) -> User | None:
        """Find user by email address with organization and role preloaded."""
        stmt = (
            select(User)
            .options(selectinload(User.organization), selectinload(User.role))
            .where(User.email == email.lower().strip())
        )
        if not include_deleted:
            stmt = stmt.where(User.deleted_at.is_(None))
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_org(
        self,
        org_id: uuid.UUID,
        *,
        skip: int = 0,
        limit: int = 100,
        include_inactive: bool = False,
    ) -> Sequence[User]:
        """List users belonging to a specific organization."""
        stmt = (
            select(User)
            .options(selectinload(User.role))
            .where(User.org_id == org_id)
            .where(User.deleted_at.is_(None))
        )
        if not include_inactive:
            stmt = stmt.where(User.is_active.is_(True))
        stmt = stmt.order_by(User.full_name.asc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def record_login(self, user_id: uuid.UUID) -> None:
        """Update last login timestamp and reset failed login counter."""
        user = await self.get_by_id(user_id)
        if user:
            user.last_login_at = datetime.now(UTC)
            user.failed_login_attempts = 0
            user.locked_until = None
            await self.session.flush()

    async def increment_failed_login(
        self,
        user_id: uuid.UUID,
        *,
        lock_until: datetime | None = None,
    ) -> int:
        """Increment failed login attempts and optionally lock the account."""
        user = await self.get_by_id(user_id)
        if user:
            user.failed_login_attempts += 1
            if lock_until:
                user.locked_until = lock_until
            await self.session.flush()
            return user.failed_login_attempts
        return 0

    async def reset_failed_login(self, user_id: uuid.UUID) -> None:
        """Clear failed attempts and unlock account."""
        user = await self.get_by_id(user_id)
        if user:
            user.failed_login_attempts = 0
            user.locked_until = None
            await self.session.flush()

    async def count_by_org(self, org_id: uuid.UUID) -> int:
        """Return the total count of active, non-deleted users in an organization."""
        from sqlalchemy import func, select

        stmt = (
            select(func.count())
            .select_from(User)
            .where(User.org_id == org_id)
            .where(User.deleted_at.is_(None))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one()
