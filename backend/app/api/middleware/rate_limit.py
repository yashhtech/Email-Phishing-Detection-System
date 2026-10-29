"""Global per-route and global request rate limiting middleware.

Uses a sliding-window counter in Redis. Falls back gracefully if Redis
is unavailable (logs a warning and allows the request through).

Configuration
-------------
The middleware applies different limits per route prefix:
    /api/v1/auth/login    →  10 req / 60 s per IP
    /api/v1/auth/register →   5 req / 600 s per IP
    /api/v1/auth/*        →  30 req / 60 s per IP
    /api/v1/*             → 120 req / 60 s per IP (global API limit)

Limits are intentionally generous for most routes and tight for
authentication endpoints to mitigate credential stuffing.
"""

from __future__ import annotations

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = structlog.get_logger(__name__)

# (path_prefix, max_requests, window_seconds)
_LIMITS: list[tuple[str, int, int]] = [
    ("/api/v1/auth/login", 10, 60),
    ("/api/v1/auth/register", 5, 600),
    ("/api/v1/auth/", 30, 60),
    ("/api/v1/", 120, 60),
]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter applied at the middleware layer."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        ip = request.client.host if request.client else "unknown"

        # Find the first matching rule
        limit_config: tuple[int, int] | None = None
        matched_prefix: str = ""
        for prefix, max_req, window in _LIMITS:
            if path.startswith(prefix):
                limit_config = (max_req, window)
                matched_prefix = prefix
                break

        if limit_config is None:
            return await call_next(request)

        max_requests, window_seconds = limit_config

        from app.infrastructure.cache.redis_client import (
            get_redis_client,
            is_redis_circuit_open,
        )

        if is_redis_circuit_open():
            return await call_next(request)

        try:
            redis = await get_redis_client()
            key = f"rate:{matched_prefix}:{ip}"
            count = await redis.incr(key)
            if count == 1:
                await redis.expire(key, window_seconds)

            # Reject BEFORE processing when over the limit
            if count > max_requests:
                logger.warning(
                    "rate_limit_exceeded",
                    ip=ip,
                    path=path,
                    count=count,
                    limit=max_requests,
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": "Too many requests. Please slow down.",
                        },
                    },
                    headers={
                        "X-RateLimit-Limit": str(max_requests),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Window": str(window_seconds),
                        "Retry-After": str(window_seconds),
                    },
                )

            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(max_requests)
            response.headers["X-RateLimit-Remaining"] = str(max(0, max_requests - count))
            response.headers["X-RateLimit-Window"] = str(window_seconds)
            return response

        except Exception as exc:
            # Never block a request due to Redis being down; trigger circuit cooldown
            from app.infrastructure.cache.redis_client import record_redis_failure

            record_redis_failure()
            logger.warning("rate_limit_middleware_error", error=str(exc))
            return await call_next(request)

