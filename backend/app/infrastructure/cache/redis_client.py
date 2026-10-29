"""Redis async client adapter.

Provides a single shared Redis connection pool for the application.
All Redis access should go through this module.
"""

from __future__ import annotations

from typing import Any

import redis.asyncio as aioredis

from app.infrastructure.config.settings import get_settings

_redis_client: aioredis.Redis | None = None  # type: ignore[type-arg]
_last_redis_failure: float = 0.0
_REDIS_RETRY_COOLDOWN_SECONDS: float = 5.0


def is_redis_circuit_open() -> bool:
    """Return True if Redis was recently detected as unreachable and in cooldown."""
    import time
    return (time.monotonic() - _last_redis_failure) < _REDIS_RETRY_COOLDOWN_SECONDS


def record_redis_failure() -> None:
    """Record connection failure to trigger cooldown period."""
    global _last_redis_failure
    import time
    _last_redis_failure = time.monotonic()


async def get_redis_client() -> aioredis.Redis:  # type: ignore[type-arg]
    """Return the shared Redis async client (singleton)."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = aioredis.from_url(
            settings.redis_url,
            max_connections=settings.redis_max_connections,
            decode_responses=True,
            socket_connect_timeout=0.5,
            socket_timeout=1.0,
            socket_keepalive=True,
        )
    return _redis_client


class RedisCacheAdapter:
    """Concrete implementation of CachePort backed by Redis.

    Implements the CachePort protocol defined in application/ports/cache.py.
    """

    def __init__(self, client: aioredis.Redis) -> None:  # type: ignore[type-arg]
        self._client = client

    async def get(self, key: str) -> Any | None:
        """Retrieve a value. Returns None if not found."""
        return await self._client.get(key)

    async def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> None:
        """Store a value with optional TTL."""
        await self._client.set(key, value, ex=ttl_seconds)

    async def delete(self, key: str) -> None:
        """Remove a key."""
        await self._client.delete(key)

    async def exists(self, key: str) -> bool:
        """Check whether a key exists."""
        return bool(await self._client.exists(key))

    async def increment(self, key: str, amount: int = 1) -> int:
        """Atomically increment a counter."""
        return int(await self._client.incrby(key, amount))
