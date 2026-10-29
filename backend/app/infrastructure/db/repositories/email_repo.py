"""Repository for Email messages and associated telemetry (headers, URLs, attachments)."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.infrastructure.db.models.email import Attachment, Email, EmailHeader, EmailURL
from app.infrastructure.db.models.enums import EmailStatus
from app.infrastructure.db.repositories.base import BaseRepository


class EmailRepository(BaseRepository[Email]):
    """Data access layer for submitted emails and nested forensic data."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Email, session)

    async def get_with_relations(self, email_id: uuid.UUID) -> Email | None:
        """Fetch email along with parsed headers, extracted URLs, attachments, and analysis."""
        stmt = (
            select(Email)
            .options(
                selectinload(Email.header),
                selectinload(Email.urls),
                selectinload(Email.attachments),
                selectinload(Email.analysis),
                selectinload(Email.submitted_by_user),
            )
            .where(Email.id == email_id)
            .where(Email.deleted_at.is_(None))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_message_id(self, org_id: uuid.UUID, message_id: str) -> Email | None:
        """Look up email by RFC Message-ID within an organization to prevent duplicates."""
        stmt = (
            select(Email)
            .where(Email.org_id == org_id)
            .where(Email.message_id == message_id)
            .where(Email.deleted_at.is_(None))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_org(
        self,
        org_id: uuid.UUID,
        *,
        status: EmailStatus | None = None,
        from_domain: str | None = None,
        has_attachments: bool | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Sequence[Email]:
        """List emails for an organization with optional filtering, sorted by arrival descending."""
        stmt = select(Email).where(Email.org_id == org_id).where(Email.deleted_at.is_(None))
        if status is not None:
            stmt = stmt.where(Email.status == status)
        if from_domain is not None:
            stmt = stmt.where(Email.from_domain == from_domain.lower().strip())
        if has_attachments is not None:
            stmt = stmt.where(Email.has_attachments.is_(has_attachments))

        stmt = stmt.order_by(Email.received_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_by_org(
        self,
        org_id: uuid.UUID,
        *,
        status: EmailStatus | None = None,
    ) -> int:
        """Count emails for an organization."""
        stmt = (
            select(func.count(Email.id))
            .where(Email.org_id == org_id)
            .where(Email.deleted_at.is_(None))
        )
        if status is not None:
            stmt = stmt.where(Email.status == status)
        result = await self.session.execute(stmt)
        return int(result.scalar_one() or 0)

    async def update_status(self, email_id: uuid.UUID, status: EmailStatus) -> None:
        """Update analysis status for an email."""
        email = await self.get_by_id(email_id)
        if email:
            email.status = status
            await self.session.flush()

    async def add_header(self, header: EmailHeader) -> EmailHeader:
        """Persist parsed header information."""
        self.session.add(header)
        await self.session.flush()
        return header

    async def add_urls(self, urls: list[EmailURL]) -> list[EmailURL]:
        """Bulk persist extracted email URLs."""
        self.session.add_all(urls)
        await self.session.flush()
        return urls

    async def add_attachments(self, attachments: list[Attachment]) -> list[Attachment]:
        """Bulk persist email attachments."""
        self.session.add_all(attachments)
        await self.session.flush()
        return attachments
