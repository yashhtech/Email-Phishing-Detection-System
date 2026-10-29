"""Repository for immutable AuditLog entries."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.models.audit import AuditLog
from app.infrastructure.db.models.enums import AuditAction
from app.infrastructure.db.repositories.base import BaseRepository


class AuditLogRepository(BaseRepository[AuditLog]):
    """Data access layer for compliance and security audit trails."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(AuditLog, session)

    async def create_entry(
        self,
        *,
        event_type: str,
        action: AuditAction,
        resource_type: str,
        correlation_id: uuid.UUID,
        org_id: uuid.UUID | None = None,
        actor_user_id: uuid.UUID | None = None,
        actor_email: str | None = None,
        actor_ip: str | None = None,
        resource_id: str | None = None,
        before_state: dict[str, Any] | None = None,
        after_state: dict[str, Any] | None = None,
        metadata_payload: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Create and flush an immutable audit log record."""
        entry = AuditLog(
            event_type=event_type,
            action=action,
            resource_type=resource_type,
            correlation_id=correlation_id,
            org_id=org_id,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            actor_ip=actor_ip,
            resource_id=resource_id,
            before_state=before_state,
            after_state=after_state,
            metadata_payload=metadata_payload or {},
        )
        return await self.create(entry)

    async def list_by_org(
        self,
        org_id: uuid.UUID,
        *,
        skip: int = 0,
        limit: int = 50,
    ) -> Sequence[AuditLog]:
        """Fetch audit trail for an organization."""
        stmt = (
            select(AuditLog)
            .where(AuditLog.org_id == org_id)
            .order_by(AuditLog.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_by_user(
        self,
        user_id: uuid.UUID,
        *,
        skip: int = 0,
        limit: int = 50,
    ) -> Sequence[AuditLog]:
        """Fetch audit records initiated by a specific user."""
        stmt = (
            select(AuditLog)
            .where(AuditLog.actor_user_id == user_id)
            .order_by(AuditLog.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_by_correlation_id(
        self,
        correlation_id: uuid.UUID,
    ) -> Sequence[AuditLog]:
        """Fetch all audit events associated with a request correlation ID."""
        stmt = (
            select(AuditLog)
            .where(AuditLog.correlation_id == correlation_id)
            .order_by(AuditLog.created_at.asc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
