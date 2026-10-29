"""Generic base repository with async CRUD, filtering, transactions, and soft-delete support."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Generic, TypeVar

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.models.base_model import BaseModel, SoftDeleteMixin

ModelT = TypeVar("ModelT", bound=BaseModel)


class BaseRepository(Generic[ModelT]):
    """Generic async repository providing standard data access patterns."""

    def __init__(self, model_cls: type[ModelT], session: AsyncSession) -> None:
        self.model_cls = model_cls
        self.session = session

    async def get_by_id(
        self,
        entity_id: uuid.UUID,
        *,
        include_deleted: bool = False,
    ) -> ModelT | None:
        """Fetch a single record by primary key."""
        stmt = select(self.model_cls).where(self.model_cls.id == entity_id)
        if not include_deleted and issubclass(self.model_cls, SoftDeleteMixin):
            stmt = stmt.where(self.model_cls.deleted_at.is_(None))
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create(self, entity: ModelT) -> ModelT:
        """Persist a new entity instance."""
        self.session.add(entity)
        await self.session.flush()
        return entity

    async def update(self, entity: ModelT) -> ModelT:
        """Merge/update an entity instance."""
        await self.session.flush()
        return entity

    async def delete(
        self,
        entity_id: uuid.UUID,
        *,
        soft: bool = True,
    ) -> bool:
        """Delete an entity by ID (soft delete if supported and requested, else hard delete)."""
        entity = await self.get_by_id(entity_id, include_deleted=True)
        if entity is None:
            return False

        if soft and isinstance(entity, SoftDeleteMixin):
            entity.deleted_at = datetime.now(UTC)
            await self.session.flush()
        else:
            await self.session.delete(entity)
            await self.session.flush()
        return True

    async def list(
        self,
        *,
        skip: int = 0,
        limit: int = 100,
        include_deleted: bool = False,
    ) -> Sequence[ModelT]:
        """Fetch paginated records ordered by created_at descending."""
        stmt = select(self.model_cls)
        if not include_deleted and issubclass(self.model_cls, SoftDeleteMixin):
            stmt = stmt.where(self.model_cls.deleted_at.is_(None))
        stmt = stmt.order_by(self.model_cls.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count(self, *, include_deleted: bool = False) -> int:
        """Count total matching records."""
        stmt = select(func.count(self.model_cls.id))
        if not include_deleted and issubclass(self.model_cls, SoftDeleteMixin):
            stmt = stmt.where(self.model_cls.deleted_at.is_(None))
        result = await self.session.execute(stmt)
        return int(result.scalar_one() or 0)
