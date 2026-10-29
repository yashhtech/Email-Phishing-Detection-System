"""Cache port interface."""

from __future__ import annotations

from typing import Any, Protocol


class CachePort(Protocol):
    """Abstract cache interface.

    Application services use this protocol — never redis directly.
    """

    async def get(self, key: str) -> Any | None:
        """Retrieve a value by key. Returns None if not found or expired."""
        ...

    async def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> None:
        """Store a value with optional TTL in seconds."""
        ...

    async def delete(self, key: str) -> None:
        """Remove a key."""
        ...

    async def exists(self, key: str) -> bool:
        """Check whether a key exists."""
        ...

    async def increment(self, key: str, amount: int = 1) -> int:
        """Atomically increment a counter and return the new value."""
        ...
