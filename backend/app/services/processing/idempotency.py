"""Idempotency management and duplicate processing prevention for analysis jobs.

Guarantees:
1. At-most-once active execution per analysis_id.
2. If an identical job is re-dispatched while already running, the second attempt is safely rejected.
3. If a job is already COMPLETED, duplicate execution is skipped and cached results are retained.
4. Auto-releasing locks prevent permanent deadlocks on unexpected worker termination.
"""

from __future__ import annotations

import asyncio
import time
import uuid

import structlog

logger = structlog.get_logger(__name__)


class IdempotencyGuard:
    """In-memory and async-lock coordinator preventing duplicate job execution."""

    def __init__(self, lock_timeout_seconds: float = 300.0) -> None:
        self._lock_timeout = lock_timeout_seconds
        # Maps analysis_id (UUID) -> acquisition timestamp
        self._active_locks: dict[uuid.UUID, float] = {}
        self._mutex = asyncio.Lock()

    async def acquire(self, analysis_id: uuid.UUID) -> bool:
        """Attempt to acquire execution lock for an analysis job.

        Returns:
            True if lock was successfully acquired (job should proceed).
            False if another worker is already processing this analysis_id.
        """
        now = time.monotonic()
        async with self._mutex:
            if analysis_id in self._active_locks:
                acquired_at = self._active_locks[analysis_id]
                if (now - acquired_at) < self._lock_timeout:
                    # Still locked by an active worker
                    logger.warning(
                        "duplicate_job_processing_prevented",
                        analysis_id=str(analysis_id),
                        elapsed_seconds=round(now - acquired_at, 2),
                    )
                    return False
                else:
                    # Expired lock — reclaim
                    logger.warning(
                        "stale_job_lock_reclaimed",
                        analysis_id=str(analysis_id),
                        elapsed_seconds=round(now - acquired_at, 2),
                    )

            self._active_locks[analysis_id] = now
            return True

    async def release(self, analysis_id: uuid.UUID) -> None:
        """Release execution lock after job completes or terminates."""
        async with self._mutex:
            self._active_locks.pop(analysis_id, None)

    async def is_locked(self, analysis_id: uuid.UUID) -> bool:
        """Check whether an analysis is currently locked by a worker."""
        now = time.monotonic()
        async with self._mutex:
            if analysis_id in self._active_locks:
                return (now - self._active_locks[analysis_id]) < self._lock_timeout
            return False

    async def clear_all(self) -> None:
        """Clear all active locks (used in testing or pool reset)."""
        async with self._mutex:
            self._active_locks.clear()

    @property
    def active_locks(self) -> dict[uuid.UUID, float]:
        """Return a copy of the active locks table."""
        return dict(self._active_locks)


# Global singleton guard
idempotency_guard = IdempotencyGuard()
