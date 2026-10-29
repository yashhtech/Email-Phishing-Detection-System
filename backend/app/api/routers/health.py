"""Health check endpoints.

GET /api/v1/health — Liveness + readiness probe.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.infrastructure.cache.redis_client import (
    get_redis_client,
    is_redis_circuit_open,
    record_redis_failure,
)
from app.infrastructure.config.settings import get_settings
from app.infrastructure.db.session import engine
from app.services.processing.worker import get_worker_pool

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get(
    "/health/live",
    summary="Liveness check",
    description="Simple probe to check if the application process is running and accepting traffic.",
    tags=["health"],
)
async def liveness_check() -> dict[str, str]:
    """Lightweight liveness probe for cloud load balancers."""
    return {"status": "alive", "timestamp": datetime.now(UTC).isoformat()}


@router.get(
    "/health/ready",
    summary="Readiness check",
    description="Readiness probe verifying database connectivity and worker pool status.",
    tags=["health"],
)
async def readiness_check() -> JSONResponse:
    """Readiness probe checking critical database dependency."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "ready", "timestamp": datetime.now(UTC).isoformat()},
        )
    except Exception as exc:
        logger.error("readiness_check_failed", error=str(exc))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "error": "Database unreachable", "timestamp": datetime.now(UTC).isoformat()},
        )


@router.get(
    "/health",
    summary="Health check",
    description="Liveness and readiness probe. Returns 200 if healthy, 503 if critical dependencies are degraded.",
    response_description="Health status of all system components",
    tags=["health"],
)
async def health_check() -> JSONResponse:
    """Check liveness and readiness of all dependencies with cloud free-tier fallback support."""
    settings = get_settings()
    checks: dict[str, dict[str, object]] = {}
    overall_healthy = True

    # --- Database check ---
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = {"status": "ok"}
    except Exception as exc:
        logger.error("health_check_db_failed", error=str(exc))
        checks["database"] = {"status": "error", "detail": "Database unreachable"}
        overall_healthy = False

    # --- Redis check (with free-tier standalone fallback) ---
    if is_redis_circuit_open():
        if settings.redis_required:
            checks["redis"] = {"status": "error", "detail": "Redis unreachable (circuit open)"}
            overall_healthy = False
        else:
            checks["redis"] = {
                "status": "degraded",
                "mode": "in_memory_fallback",
                "detail": "Redis circuit open; operating in standalone in-memory mode",
            }
    else:
        try:
            redis = await get_redis_client()
            await redis.ping()
            checks["redis"] = {"status": "ok", "mode": "redis"}
        except Exception as exc:
            record_redis_failure()
            logger.warning("health_check_redis_warning", error=str(exc))
            if settings.redis_required:
                checks["redis"] = {"status": "error", "detail": "Redis unreachable"}
                overall_healthy = False
            else:
                checks["redis"] = {
                    "status": "degraded",
                    "mode": "in_memory_fallback",
                    "detail": "Redis unavailable; operating in standalone in-memory mode",
                }

    # --- Worker Pool check ---
    worker_pool = get_worker_pool()
    worker_health = worker_pool.get_health()
    checks["worker_pool"] = {
        "status": worker_health.status,
        "active_workers": worker_health.active_workers,
        "queue_depth": worker_health.queue_depth,
        "completed_jobs": worker_health.completed_jobs,
    }

    # --- Groq LLM status ---
    checks["groq_llm"] = {
        "status": "configured" if settings.groq_api_key is not None else "unconfigured",
        "model": settings.groq_model,
    }

    payload = {
        "status": "healthy" if overall_healthy else "unhealthy",
        "version": "1.0.0",
        "environment": settings.app_env,
        "timestamp": datetime.now(UTC).isoformat(),
        "checks": checks,
    }

    return JSONResponse(
        content=payload,
        status_code=status.HTTP_200_OK if overall_healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
    )
