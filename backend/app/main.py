"""FastAPI application entry point."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.api.exception_handlers import register_exception_handlers
from app.api.middleware.correlation import CorrelationIDMiddleware
from app.api.middleware.rate_limit import RateLimitMiddleware
from app.api.middleware.security_headers import SecurityHeadersMiddleware
from app.api.middleware.timing import ResponseTimingMiddleware
from app.api.routers.analysis import router as analysis_router
from app.api.routers.analytics import router as analytics_router
from app.api.routers.auth import router as auth_router
from app.api.routers.dashboard import router as dashboard_router
from app.api.routers.emails import router as emails_router
from app.api.routers.health import router as health_router
from app.api.routers.reports import router as reports_router
from app.api.routers.threats import router as threats_router
from app.api.routers.users import router as users_router
from app.infrastructure.cache.redis_client import get_redis_client
from app.infrastructure.config.settings import get_settings
from app.infrastructure.db.session import engine
from app.infrastructure.logging.setup import configure_logging
from app.services.processing.worker import get_worker_pool

logger = structlog.get_logger(__name__)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application lifespan — startup and shutdown."""
    settings = get_settings()
    configure_logging(settings.log_level, settings.app_env)
    logger.info("app_starting", app_env=settings.app_env, version="1.0.0")

    # Check Redis connectivity on startup (log warning if unavailable)
    try:
        redis = await get_redis_client()
        await redis.ping()
        logger.info("redis_connected")
    except Exception as exc:
        logger.warning("redis_connection_failed_at_startup", error=str(exc))

    # Start background analysis worker pool
    worker_pool = get_worker_pool()
    await worker_pool.start()
    logger.info("analysis_worker_pool_started")

    yield

    # Shutdown: stop worker pool, close DB engine and Redis
    logger.info("app_shutting_down")
    try:
        await worker_pool.stop()
        logger.info("analysis_worker_pool_stopped")
    except Exception as exc:
        logger.warning("worker_pool_stop_error", error=str(exc))
    try:
        await engine.dispose()
    except Exception as exc:
        logger.warning("db_dispose_error", error=str(exc))

    try:
        redis = await get_redis_client()
        await redis.close()
    except Exception as exc:
        logger.warning("redis_close_error", error=str(exc))


def create_app() -> FastAPI:
    """Application factory — creates and configures the FastAPI app."""
    settings = get_settings()

    app = FastAPI(
        title="Email Threat Detection API",
        description="AI-powered email threat detection and security intelligence platform.",
        version="1.0.0",
        docs_url=None if settings.app_env == "production" else "/docs",
        redoc_url=None if settings.app_env == "production" else "/redoc",
        openapi_url=None if settings.app_env == "production" else "/openapi.json",
        lifespan=lifespan,
    )

    # --- Middleware (outermost first) ---
    # CORS must be first so preflight requests are handled before auth checks
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_origin_regex=settings.cors_origin_regex,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(ResponseTimingMiddleware)
    app.add_middleware(CorrelationIDMiddleware)

    # --- Exception handlers ---
    register_exception_handlers(app)

    # --- Root health endpoints (for cloud providers like Render / Kubernetes) ---
    app.include_router(health_router, tags=["health"])

    # --- Routers ---
    api_prefix = "/api/v1"
    app.include_router(health_router, prefix=api_prefix, tags=["health"])
    app.include_router(auth_router, prefix=api_prefix, tags=["Authentication"])
    app.include_router(users_router, prefix=api_prefix, tags=["Users"])
    app.include_router(emails_router, prefix=api_prefix, tags=["Email Analyzer"])
    app.include_router(analysis_router, prefix=api_prefix)
    app.include_router(dashboard_router, prefix=api_prefix, tags=["Dashboard"])
    app.include_router(analytics_router, prefix=api_prefix, tags=["Analytics"])
    app.include_router(reports_router, prefix=api_prefix, tags=["Reports"])
    app.include_router(threats_router, prefix=api_prefix, tags=["Threat Intelligence"])

    if settings.app_env != "production" or settings.demo_mode:
        from app.api.routers.dev import router as dev_router

        app.include_router(dev_router, prefix=api_prefix)

    # Dedicated WebSocket router at root level — prevents REST routes from bypassing /api/v1
    from fastapi import APIRouter

    from app.api.routers.analysis import websocket_analysis_endpoint
    from app.api.routers.dashboard import websocket_dashboard_endpoint

    ws_router = APIRouter(tags=["WebSockets"])
    ws_router.add_api_websocket_route("/ws/analysis/{analysis_id}", websocket_analysis_endpoint)
    ws_router.add_api_websocket_route("/ws/dashboard", websocket_dashboard_endpoint)
    app.include_router(ws_router)

    return app


app = create_app()
