"""Unit tests for asynchronous email analysis pipeline, worker pool, and idempotency guard.

Tests:
- IdempotencyGuard: acquisition, duplicate rejection, release, stale lock timeout
- AnalysisWorkerPool: enqueueing, worker processing, retry handling, max retry exhaustion, graceful drain
- WorkerHealthStatus: active worker counts, queue depth, uptime calculation
- WebSocketConnectionManager: connection management, targeted broadcasts, dead client cleanup
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.infrastructure.websocket.manager import WebSocketConnectionManager
from app.services.processing.idempotency import IdempotencyGuard
from app.services.processing.schemas import (
    AnalysisJob,
    AnalysisStage,
    AnalysisSubmitResult,
    JobStatus,
)
from app.services.processing.worker import AnalysisWorkerPool

# ===========================================================================
# 1. Idempotency Guard Tests
# ===========================================================================


class TestIdempotencyGuard:
    """Validate duplicate processing prevention and stale lock reclaiming."""

    @pytest.mark.asyncio
    async def test_acquire_lock_success(self) -> None:
        guard = IdempotencyGuard(lock_timeout_seconds=60)
        aid = uuid.uuid4()

        acquired = await guard.acquire(aid)
        assert acquired is True
        assert await guard.is_locked(aid) is True

    @pytest.mark.asyncio
    async def test_duplicate_acquisition_rejected(self) -> None:
        guard = IdempotencyGuard(lock_timeout_seconds=60)
        aid = uuid.uuid4()

        first = await guard.acquire(aid)
        second = await guard.acquire(aid)

        assert first is True
        assert second is False  # Rejected duplicate

    @pytest.mark.asyncio
    async def test_release_allows_reacquisition(self) -> None:
        guard = IdempotencyGuard(lock_timeout_seconds=60)
        aid = uuid.uuid4()

        await guard.acquire(aid)
        await guard.release(aid)

        assert await guard.is_locked(aid) is False
        reacquired = await guard.acquire(aid)
        assert reacquired is True

    @pytest.mark.asyncio
    async def test_stale_lock_auto_reclaimed(self) -> None:
        # 0.05 second timeout for fast testing
        guard = IdempotencyGuard(lock_timeout_seconds=0.05)
        aid = uuid.uuid4()

        await guard.acquire(aid)
        assert await guard.is_locked(aid) is True

        # Wait until lock expires
        await asyncio.sleep(0.08)

        # Should be re-acquirable because old lock expired
        acquired_after_expiry = await guard.acquire(aid)
        assert acquired_after_expiry is True

    @pytest.mark.asyncio
    async def test_clear_all_resets_guard(self) -> None:
        guard = IdempotencyGuard(lock_timeout_seconds=60)
        aid1 = uuid.uuid4()
        aid2 = uuid.uuid4()

        await guard.acquire(aid1)
        await guard.acquire(aid2)
        assert len(guard.active_locks) == 2

        await guard.clear_all()
        assert len(guard.active_locks) == 0


# ===========================================================================
# 2. Worker Pool & Job Execution Tests
# ===========================================================================


class TestAnalysisWorkerPool:
    """Validate background worker pool lifecycle, retries, and telemetry."""

    @pytest.mark.asyncio
    async def test_worker_pool_lifecycle(self) -> None:
        guard = IdempotencyGuard(lock_timeout_seconds=60)
        pool = AnalysisWorkerPool(max_workers=2, guard=guard)

        health_before = pool.get_health()
        assert health_before.status == "stopped"
        assert health_before.active_workers == 0

        await pool.start()
        health_running = pool.get_health()
        assert health_running.status == "healthy"
        assert health_running.active_workers == 2
        assert health_running.uptime_seconds >= 0

        await pool.stop(timeout_seconds=2.0)
        health_stopped = pool.get_health()
        assert health_stopped.status == "stopped"

    @pytest.mark.asyncio
    async def test_worker_processes_job_successfully(self) -> None:
        guard = IdempotencyGuard(lock_timeout_seconds=60)
        pool = AnalysisWorkerPool(max_workers=1, guard=guard)
        await pool.start()

        job = AnalysisJob(
            job_id="job-test-1",
            analysis_id=uuid.uuid4(),
            email_id=uuid.uuid4(),
            org_id=uuid.uuid4(),
            raw_content="From: test@example.com\nTo: dest@example.com\n\nHello",
        )

        with patch(
            "app.services.processing.worker.execute_analysis_pipeline", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = None
            await pool.enqueue(job)

            # Wait briefly for worker to consume
            await asyncio.sleep(0.1)
            mock_exec.assert_awaited_once_with(job)

        health = pool.get_health()
        assert health.completed_jobs == 1
        assert health.failed_jobs == 0

        await pool.stop(timeout_seconds=2.0)

    @pytest.mark.asyncio
    async def test_worker_rejects_duplicate_in_flight_job(self) -> None:
        guard = IdempotencyGuard(lock_timeout_seconds=60)
        pool = AnalysisWorkerPool(max_workers=1, guard=guard)

        aid = uuid.uuid4()
        # Manually lock aid in guard
        await guard.acquire(aid)

        job = AnalysisJob(
            job_id="job-duplicate-test",
            analysis_id=aid,
            email_id=uuid.uuid4(),
            org_id=uuid.uuid4(),
        )

        with patch(
            "app.services.processing.worker.execute_analysis_pipeline", new_callable=AsyncMock
        ) as mock_exec:
            await pool.start()
            await pool.enqueue(job)
            await asyncio.sleep(0.1)

            # Pipeline should NOT have been called because duplicate was rejected
            mock_exec.assert_not_awaited()

        await pool.stop(timeout_seconds=2.0)

    @pytest.mark.asyncio
    async def test_worker_retries_transient_failure_and_exhausts(self) -> None:
        guard = IdempotencyGuard(lock_timeout_seconds=60)
        pool = AnalysisWorkerPool(max_workers=1, guard=guard)

        job = AnalysisJob(
            job_id="job-retry-fail",
            analysis_id=uuid.uuid4(),
            email_id=uuid.uuid4(),
            org_id=uuid.uuid4(),
            max_retries=1,  # Only 1 retry for fast test
        )

        with (
            patch(
                "app.services.processing.worker.execute_analysis_pipeline", new_callable=AsyncMock
            ) as mock_exec,
            patch("app.services.processing.worker._RETRY_DELAYS", [0.01, 0.02]),
        ):
            mock_exec.side_effect = RuntimeError("Simulated transient connection timeout")

            await pool.start()
            await pool.enqueue(job)

            # Wait for initial attempt + 1 retry
            await asyncio.sleep(0.15)

            # Called twice: attempt 1 + attempt 2
            assert mock_exec.await_count == 2

        health = pool.get_health()
        assert health.failed_jobs == 1
        assert health.completed_jobs == 0

        await pool.stop(timeout_seconds=2.0)


# ===========================================================================
# 3. WebSocket Connection Manager Tests
# ===========================================================================


class TestWebSocketManager:
    """Validate real-time event broadcasting and multi-client dispatch."""

    @pytest.mark.asyncio
    async def test_connect_and_broadcast_to_subscriber(self) -> None:
        mgr = WebSocketConnectionManager()
        analysis_id = "analysis-ws-123"

        mock_ws = AsyncMock()
        mock_ws.accept = AsyncMock()
        mock_ws.send_json = AsyncMock()

        await mgr.connect(mock_ws, analysis_id)
        assert mgr.subscriber_count(analysis_id) == 1

        sent_count = await mgr.broadcast_event(
            analysis_id=analysis_id,
            status="processing",
            stage="ml_engine",
            data={"probability": 0.88},
        )
        assert sent_count == 1
        mock_ws.send_json.assert_awaited_once()
        payload = mock_ws.send_json.call_args[0][0]
        assert payload["analysis_id"] == analysis_id
        assert payload["stage"] == "ml_engine"
        assert payload["status"] == "processing"

    @pytest.mark.asyncio
    async def test_disconnect_removes_client(self) -> None:
        mgr = WebSocketConnectionManager()
        analysis_id = "analysis-ws-456"

        mock_ws = AsyncMock()
        await mgr.connect(mock_ws, analysis_id)
        assert mgr.subscriber_count(analysis_id) == 1

        await mgr.disconnect(mock_ws, analysis_id)
        assert mgr.subscriber_count(analysis_id) == 0

    @pytest.mark.asyncio
    async def test_dead_client_automatically_cleaned_up(self) -> None:
        mgr = WebSocketConnectionManager()
        analysis_id = "analysis-ws-dead"

        dead_ws = AsyncMock()
        dead_ws.accept = AsyncMock()
        dead_ws.send_json = AsyncMock(side_effect=RuntimeError("Client disconnected unexpectedly"))

        await mgr.connect(dead_ws, analysis_id)
        assert mgr.subscriber_count(analysis_id) == 1

        # Broadcast should gracefully handle error and purge client
        sent = await mgr.broadcast_event(
            analysis_id=analysis_id, status="processing", stage="preprocessing"
        )
        assert sent == 0
        assert mgr.subscriber_count(analysis_id) == 0


# ===========================================================================
# 4. Schemas & Status Contracts Tests
# ===========================================================================


class TestProcessingSchemas:
    """Validate Pydantic models and stage enums."""

    def test_job_status_values(self) -> None:
        assert JobStatus.QUEUED.value == "queued"
        assert JobStatus.PROCESSING.value == "processing"
        assert JobStatus.COMPLETED.value == "completed"
        assert JobStatus.FAILED.value == "failed"

    def test_analysis_stages_coverage(self) -> None:
        stages = [s.value for s in AnalysisStage]
        assert "preprocessing" in stages
        assert "security_engine" in stages
        assert "ml_engine" in stages
        assert "threat_intel" in stages
        assert "groq_llm" in stages
        assert "risk_engine" in stages
        assert "persistence" in stages
        assert "completed" in stages
        assert "failed" in stages

    def test_analysis_submit_result_schema(self) -> None:
        now = datetime.now(UTC)
        aid = uuid.uuid4()
        eid = uuid.uuid4()
        result = AnalysisSubmitResult(
            analysis_id=aid,
            email_id=eid,
            status=JobStatus.QUEUED,
            created_at=now,
            tracking_url=f"/api/v1/analysis/{aid}",
            websocket_url=f"/ws/analysis/{aid}",
        )
        assert result.analysis_id == aid
        assert result.status == JobStatus.QUEUED
        assert result.tracking_url == f"/api/v1/analysis/{aid}"


# ===========================================================================
# 5. Analysis API Router Tests
# ===========================================================================


class TestAnalysisAPI:
    """Validate async analysis REST endpoints."""

    @pytest.mark.asyncio
    async def test_worker_health_endpoint(self, async_client: AsyncClient) -> None:
        response = await async_client.get("/api/v1/analysis/worker/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "active_workers" in data
        assert "active_jobs" in data
        assert "completed_jobs" in data
        assert "queue_depth" in data
        assert "uptime_seconds" in data

    @pytest.mark.asyncio
    async def test_submit_analysis_enqueues_and_returns_immediately(
        self, async_client: AsyncClient
    ) -> None:
        mock_uow = MagicMock()
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None
        mock_uow.session = mock_session

        mock_org = MagicMock()
        mock_org.id = uuid.uuid4()
        mock_exec_result = MagicMock()
        mock_exec_result.scalar_one_or_none.return_value = mock_org
        mock_session.execute = AsyncMock(return_value=mock_exec_result)

        mock_session.flush = AsyncMock()
        mock_uow.commit = AsyncMock()

        from app.api.dependencies import get_uow
        from app.main import app

        app.dependency_overrides[get_uow] = lambda: mock_uow

        try:
            with patch(
                "app.api.routers.analysis.submit_analysis_job", new_callable=AsyncMock
            ) as mock_submit:
                response = await async_client.post(
                    "/api/v1/analysis",
                    json={
                        "raw_content": "From: test@example.com\nTo: dest@example.com\nSubject: Test\n\nBody",
                    },
                )
                assert response.status_code == 202
                data = response.json()
                assert data["status"] == "queued"
                assert "analysis_id" in data
                assert "email_id" in data
                assert "/api/v1/analysis/" in data["tracking_url"]
                assert "/ws/analysis/" in data["websocket_url"]
                mock_submit.assert_awaited_once()
        finally:
            app.dependency_overrides.pop(get_uow, None)

    @pytest.mark.asyncio
    async def test_get_analysis_not_found(self, async_client: AsyncClient) -> None:
        mock_uow = MagicMock()
        mock_uow.__aenter__.return_value = mock_uow
        mock_uow.__aexit__.return_value = None
        mock_uow.analyses.get_with_full_details = AsyncMock(return_value=None)

        from app.api.dependencies import get_uow
        from app.main import app

        app.dependency_overrides[get_uow] = lambda: mock_uow
        try:
            fake_id = uuid.uuid4()
            response = await async_client.get(f"/api/v1/analysis/{fake_id}")
            assert response.status_code == 404
        finally:
            app.dependency_overrides.pop(get_uow, None)
