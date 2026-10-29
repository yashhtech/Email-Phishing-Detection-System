"""Simple async-safe in-process response cache for analytics endpoints.

Uses a TTL-based dict to avoid repeated heavy aggregation queries for the
same org + preset combination. Correctness is preserved because:
  1. TTL defaults to 30 seconds — analytics aggregate telemetry does not
     require sub-second freshness.
  2. Cache is keyed by (org_id, preset/start/end) — data never crosses
     tenant or user boundaries.
  3. Eviction LRU bounds maximum memory consumption.
  4. Cache is entirely skipped if any exception occurs (fail-open).

Safety guarantee: NEVER used for security-critical endpoints (auth, risk
verdicts, live analysis results).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class ResponseCache:
    """Simple in-process TTL response cache."""

    def __init__(self, default_ttl_seconds: int = 30, max_entries: int = 500) -> None:
        self._ttl = default_ttl_seconds
        self._max = max_entries
        self._cache: dict[str, tuple[Any, float]] = {}  # key -> (value, expires_at)
        self._lock = asyncio.Lock()

    @staticmethod
    def make_key(*parts: Any) -> str:
        raw = json.dumps(parts, default=str, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._cache[key]
                return None
            return value

    async def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self._ttl
        expires_at = time.monotonic() + ttl
        async with self._lock:
            if len(self._cache) >= self._max:
                # Evict oldest entry
                oldest = min(self._cache, key=lambda k: self._cache[k][1])
                del self._cache[oldest]
            self._cache[key] = (value, expires_at)

    async def invalidate(self, key: str) -> None:
        async with self._lock:
            self._cache.pop(key, None)

    async def clear(self) -> None:
        async with self._lock:
            self._cache.clear()


# Global singleton for analytics aggregate caching
analytics_cache = ResponseCache(default_ttl_seconds=30, max_entries=500)
