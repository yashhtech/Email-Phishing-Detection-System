"""Async background worker pool for email analysis jobs.

Responsibilities:
1. Consume AnalysisJob payloads from an in-memory async queue (no Celery dependency).
2. Enforce idempotency via IdempotencyGuard to prevent duplicate processing.
3. Implement retry with bounded exponential backoff for transient errors.
4. Emit real-time structured job logs per attempt.
5. Expose worker health check metrics: uptime, active workers, queue depth, completion counts.
6. Support graceful shutdown without dropping in-flight jobs.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import structlog

from app.services.processing.idempotency import IdempotencyGuard, idempotency_guard
from app.services.processing.pipeline import execute_analysis_pipeline
from app.services.processing.schemas import AnalysisJob, WorkerHealthStatus

logger = structlog.get_logger(__name__)

# Retry backoff intervals per attempt (seconds): 5s, 15s, 45s
_RETRY_DELAYS = [5.0, 15.0, 45.0]


class AnalysisWorkerPool:
    """Async worker pool managing concurrent analysis job execution with retry and health checks."""

    def __init__(
        self,
        max_workers: int = 5,
        guard: IdempotencyGuard | None = None,
    ) -> None:
        self._max_workers = max_workers
        self._guard = guard or idempotency_guard
        self._queue: asyncio.Queue[AnalysisJob] = asyncio.Queue()

        # Telemetry counters
        self._active_jobs: set[str] = set()
        self._completed_count = 0
        self._failed_count = 0
        self._worker_tasks: list[asyncio.Task[None]] = []
        self._started_at: float = time.monotonic()
        self._running = False
        self._last_heartbeat: datetime = datetime.now(UTC)

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def start(self) -> None:
        """Start the worker pool — launch worker coroutines."""
        if self._running:
            return
        self._running = True
        self._started_at = time.monotonic()
        for i in range(self._max_workers):
            task = asyncio.create_task(self._worker_loop(worker_id=i), name=f"analysis_worker_{i}")
            self._worker_tasks.append(task)
        logger.info("analysis_worker_pool_started", max_workers=self._max_workers)

    async def stop(self, timeout_seconds: float = 30.0) -> None:
        """Gracefully stop the pool, waiting for in-flight jobs to finish."""
        self._running = False
        try:
            await asyncio.wait_for(
                self._wait_for_queue_drain(),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            logger.warning("worker_pool_shutdown_timeout_exceeded")

        for task in self._worker_tasks:
            task.cancel()

        self._worker_tasks.clear()
        logger.info("analysis_worker_pool_stopped")

    async def enqueue(self, job: AnalysisJob) -> None:
        """Enqueue a job for async background processing."""
        await self._queue.put(job)
        logger.info(
            "analysis_job_enqueued",
            analysis_id=str(job.analysis_id),
            job_id=job.job_id,
            queue_depth=self._queue.qsize(),
        )

    def enqueue_nowait(self, job: AnalysisJob) -> None:
        """Synchronously enqueue without blocking. Raises if queue is full."""
        self._queue.put_nowait(job)

    def get_health(self) -> WorkerHealthStatus:
        """Return real-time operational telemetry."""
        self._last_heartbeat = datetime.now(UTC)
        uptime = time.monotonic() - self._started_at
        active_worker_count = sum(1 for t in self._worker_tasks if not t.done())

        status = "stopped"
        if self._running:
            status = "healthy" if active_worker_count > 0 else "degraded"

        return WorkerHealthStatus(
            status=status,
            active_workers=active_worker_count,
            active_jobs=len(self._active_jobs),
            completed_jobs=self._completed_count,
            failed_jobs=self._failed_count,
            queue_depth=self._queue.qsize(),
            uptime_seconds=round(uptime, 2),
            last_heartbeat=self._last_heartbeat,
        )

    # -------------------------------------------------------------------------
    # Internal Worker Loop
    # -------------------------------------------------------------------------

    async def _worker_loop(self, worker_id: int) -> None:
        """Single worker coroutine — processes jobs from queue until stopped."""
        logger.info("analysis_worker_started", worker_id=worker_id)

        while self._running:
            try:
                job = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except TimeoutError:
                continue

            await self._process_job_with_retry(job, worker_id)
            self._queue.task_done()

        logger.info("analysis_worker_stopped", worker_id=worker_id)

    async def _process_job_with_retry(self, job: AnalysisJob, worker_id: int) -> None:
        """Execute job with idempotency enforcement and automatic retry on failure."""
        analysis_id_str = str(job.analysis_id)

        # Idempotency check — prevent duplicate execution
        if not await self._guard.acquire(job.analysis_id):
            logger.warning(
                "analysis_job_duplicate_rejected",
                analysis_id=analysis_id_str,
                job_id=job.job_id,
                worker_id=worker_id,
            )
            return

        self._active_jobs.add(job.job_id)
        attempt = job.attempt

        try:
            while attempt <= job.max_retries + 1:
                logger.info(
                    "analysis_job_attempt_started",
                    analysis_id=analysis_id_str,
                    job_id=job.job_id,
                    attempt=attempt,
                    max_retries=job.max_retries,
                    worker_id=worker_id,
                )

                try:
                    await execute_analysis_pipeline(job)
                    self._completed_count += 1
                    logger.info(
                        "analysis_job_completed",
                        analysis_id=analysis_id_str,
                        job_id=job.job_id,
                        attempt=attempt,
                    )
                    return  # Success

                except Exception as exc:
                    logger.warning(
                        "analysis_job_attempt_failed",
                        analysis_id=analysis_id_str,
                        job_id=job.job_id,
                        attempt=attempt,
                        error=str(exc),
                    )

                    if attempt > job.max_retries:
                        # All retries exhausted
                        logger.error(
                            "analysis_job_all_retries_exhausted",
                            analysis_id=analysis_id_str,
                            job_id=job.job_id,
                            total_attempts=attempt,
                        )
                        self._failed_count += 1
                        return

                    # Calculate backoff delay (bounded exponential)
                    delay_idx = min(attempt - 1, len(_RETRY_DELAYS) - 1)
                    delay = _RETRY_DELAYS[delay_idx]
                    logger.info(
                        "analysis_job_retry_scheduled",
                        analysis_id=analysis_id_str,
                        next_attempt=attempt + 1,
                        delay_seconds=delay,
                    )
                    await asyncio.sleep(delay)

                    # Rebuild job with incremented attempt counter
                    job = AnalysisJob(
                        job_id=job.job_id,
                        analysis_id=job.analysis_id,
                        email_id=job.email_id,
                        org_id=job.org_id,
                        attempt=attempt + 1,
                        max_retries=job.max_retries,
                        raw_content=job.raw_content,
                    )
                    attempt += 1

        finally:
            self._active_jobs.discard(job.job_id)
            await self._guard.release(job.analysis_id)

    async def _wait_for_queue_drain(self) -> None:
        """Wait for all queued jobs to be consumed."""
        await self._queue.join()


# ---------------------------------------------------------------------------
# Global singleton worker pool
# ---------------------------------------------------------------------------

# Instantiated lazily; started in FastAPI lifespan
_worker_pool: AnalysisWorkerPool | None = None


def get_worker_pool() -> AnalysisWorkerPool:
    """Return the global worker pool instance, creating it if necessary."""
    global _worker_pool
    if _worker_pool is None:
        _worker_pool = AnalysisWorkerPool(max_workers=5)
    return _worker_pool


async def submit_analysis_job(job: AnalysisJob) -> None:
    """Public helper: enqueue a job to the global worker pool."""
    pool = get_worker_pool()
    if not pool._running:
        await pool.start()
    await pool.enqueue(job)
