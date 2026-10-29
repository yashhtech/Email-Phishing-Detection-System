"""Abstract repository interfaces (ports) for the domain layer.

These protocols define the contract that infrastructure adapters must fulfill.
Application services depend only on these abstractions — never on concrete implementations.
"""

from __future__ import annotations

from typing import Any, Protocol

from app.domain.entities.email import Email, EmailStatus
from app.domain.entities.user import User


class EmailRepository(Protocol):
    """Repository contract for email persistence."""

    async def save(self, email: Email) -> Email:
        """Persist a new email entity."""
        ...

    async def find_by_id(self, email_id: str) -> Email | None:
        """Retrieve email by ULID."""
        ...

    async def find_by_message_id(self, message_id: str) -> Email | None:
        """Retrieve email by RFC 5322 Message-ID (for deduplication)."""
        ...

    async def update_status(self, email_id: str, status: EmailStatus) -> None:
        """Update only the status field."""
        ...

    async def list(
        self,
        *,
        cursor: str | None = None,
        limit: int = 20,
        filters: dict[str, Any] | None = None,
    ) -> tuple[list[Email], str | None]:
        """Return paginated list of emails and next cursor."""
        ...


class UserRepository(Protocol):
    """Repository contract for user persistence."""

    async def save(self, user: User) -> User:
        """Persist a new user."""
        ...

    async def find_by_id(self, user_id: str) -> User | None:
        """Retrieve user by ULID."""
        ...

    async def find_by_email(self, email: str) -> User | None:
        """Retrieve user by email address."""
        ...
