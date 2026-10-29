"""Thread-safe in-memory TTL caching for threat intelligence indicator checks.

Prevents redundant network round-trips to rate-limited external providers
by caching verified indicator assessments for a configurable TTL.
"""

from __future__ import annotations

import threading
import time
from typing import NamedTuple

import structlog

from app.services.threat_intelligence.schemas import IndicatorType, ThreatIntelReport

logger = structlog.get_logger(__name__)


class _CacheEntry(NamedTuple):
    report: ThreatIntelReport
    expires_at: float


class ThreatIntelCache:
    """Thread-safe TTL cache for threat intelligence query results."""

    def __init__(self, default_ttl_seconds: int = 3600, max_entries: int = 10000) -> None:
        self._default_ttl = default_ttl_seconds
        self._max_entries = max_entries
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _make_key(provider: str, indicator_type: IndicatorType | str, indicator: str) -> str:
        """Construct normalized cache key."""
        ind_type = (
            indicator_type.value
            if isinstance(indicator_type, IndicatorType)
            else str(indicator_type)
        )
        return f"{provider.lower()}:{ind_type.lower()}:{indicator.strip().lower()}"

    def get(
        self,
        provider: str,
        indicator_type: IndicatorType | str,
        indicator: str,
    ) -> ThreatIntelReport | None:
        """Retrieve cached report if present and not expired."""
        key = self._make_key(provider, indicator_type, indicator)
        now = time.monotonic()

        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None

            if entry.expires_at < now:
                # Expired
                del self._cache[key]
                return None

            # Mark as cached on return
            return entry.report.model_copy(update={"is_cached": True})

    def set(
        self,
        provider: str,
        indicator_type: IndicatorType | str,
        indicator: str,
        report: ThreatIntelReport,
        ttl_seconds: int | None = None,
    ) -> None:
        """Store indicator report with TTL."""
        key = self._make_key(provider, indicator_type, indicator)
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        expires_at = time.monotonic() + ttl

        with self._lock:
            # Simple eviction if reaching maximum capacity
            if len(self._cache) >= self._max_entries:
                self._prune_expired_locked()
                if len(self._cache) >= self._max_entries:
                    # Pop oldest arbitrary entry
                    first_key = next(iter(self._cache))
                    del self._cache[first_key]

            self._cache[key] = _CacheEntry(report=report, expires_at=expires_at)

    def _prune_expired_locked(self) -> None:
        """Remove all expired entries while holding the lock."""
        now = time.monotonic()
        expired_keys = [k for k, v in self._cache.items() if v.expires_at < now]
        for k in expired_keys:
            del self._cache[k]

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        """Return count of currently cached non-expired entries."""
        with self._lock:
            self._prune_expired_locked()
            return len(self._cache)
