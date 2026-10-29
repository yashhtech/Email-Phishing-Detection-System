"""Repository for Organization tenant entities."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.models.organization import Organization
from app.infrastructure.db.repositories.base import BaseRepository


class OrganizationRepository(BaseRepository[Organization]):
    """Data access layer for Organization accounts."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Organization, session)

    async def get_by_slug(self, slug: str) -> Organization | None:
        """Find an organization by unique URL slug."""
        stmt = (
            select(Organization)
            .where(Organization.slug == slug)
            .where(Organization.deleted_at.is_(None))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_domain(self, domain: str) -> Organization | None:
        """Find an organization by primary domain."""
        stmt = (
            select(Organization)
            .where(Organization.primary_domain == domain)
            .where(Organization.deleted_at.is_(None))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_active(self, *, skip: int = 0, limit: int = 100) -> Sequence[Organization]:
        """List active non-deleted organizations."""
        stmt = (
            select(Organization)
            .where(Organization.is_active.is_(True))
            .where(Organization.deleted_at.is_(None))
            .order_by(Organization.name.asc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
