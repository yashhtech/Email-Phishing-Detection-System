"""Refresh-token blocklist backed by Redis.

Revocation strategy
-------------------
* On **logout** the refresh token's ``jti`` is stored in Redis with a TTL
  equal to the token's remaining lifetime.  Any subsequent use of that refresh
  token will be rejected.
* On **refresh** the old refresh token is immediately revoked (rotation) and a
  fresh pair is issued.
* Access tokens are **not** revocable by default (they're short-lived, ≤ 15 min).
  If stronger guarantees are required, the same mechanism can be extended by
  also blocklisting the access token's jti.

Key schema:
    ``auth:blocklist:refresh:{jti}``  → ``"1"``  (any truthy value)
"""

from __future__ import annotations

import time
import uuid

import redis.asyncio as aioredis
import structlog

logger = structlog.get_logger(__name__)


class TokenBlocklistService:
    """Manages a Redis-backed blocklist with in-memory fallback for revoked refresh-token JTIs."""

    _PREFIX = "auth:blocklist:refresh:"
    _memory_store: dict[str, float] = {}

    def __init__(self, redis_client: aioredis.Redis | None = None) -> None:  # type: ignore[type-arg]
        self._redis = redis_client

    def _key(self, jti: uuid.UUID) -> str:
        return f"{self._PREFIX}{jti}"

    def _clean_expired_memory_keys(self) -> None:
        now = time.time()
        expired = [k for k, exp in self._memory_store.items() if exp <= now]
        for k in expired:
            self._memory_store.pop(k, None)

    async def revoke(self, jti: uuid.UUID, ttl_seconds: int) -> None:
        """Add *jti* to the blocklist, expiring after *ttl_seconds*."""
        key = self._key(jti)
        self._clean_expired_memory_keys()
        self._memory_store[key] = time.time() + ttl_seconds
        if self._redis is not None:
            try:
                await self._redis.setex(key, ttl_seconds, "1")
            except Exception as exc:
                logger.warning("redis_blocklist_revoke_fallback", error=str(exc))

    async def is_revoked(self, jti: uuid.UUID) -> bool:
        """Return True if *jti* has been revoked."""
        key = self._key(jti)
        self._clean_expired_memory_keys()
        if key in self._memory_store and self._memory_store[key] > time.time():
            return True
        if self._redis is not None:
            try:
                return bool(await self._redis.exists(key))
            except Exception as exc:
                logger.warning("redis_blocklist_check_fallback", error=str(exc))
        return False

    async def revoke_all_for_user(self, user_id: uuid.UUID, ttl_seconds: int) -> None:
        """Store a blanket user-level revocation marker."""
        user_key = f"auth:blocklist:user:{user_id}"
        self._clean_expired_memory_keys()
        self._memory_store[user_key] = time.time() + ttl_seconds
        if self._redis is not None:
            try:
                await self._redis.setex(user_key, ttl_seconds, str(int(time.time())))
            except Exception as exc:
                logger.warning("redis_blocklist_revoke_user_fallback", error=str(exc))

    async def get_user_revocation_timestamp(self, user_id: uuid.UUID) -> int | None:
        """Return the Unix timestamp at which all user tokens were revoked, or None."""
        user_key = f"auth:blocklist:user:{user_id}"
        self._clean_expired_memory_keys()
        if self._redis is not None:
            try:
                value = await self._redis.get(user_key)
                if value is not None:
                    return int(value)
            except Exception as exc:
                logger.warning("redis_blocklist_get_user_fallback", error=str(exc))
        if user_key in self._memory_store and self._memory_store[user_key] > time.time():
            return int(time.time())
        return None
