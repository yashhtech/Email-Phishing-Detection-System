"""Correlation ID middleware.

Attaches a unique request ID to every request so that all log entries
for a single request can be correlated across services.
"""

from __future__ import annotations

import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Attach a correlation ID to every request.

    Uses the incoming X-Request-ID header if present; otherwise generates
    a new UUID. The ID is bound to structlog context so it appears in all
    log entries for the request's lifetime.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Process request: inject correlation ID into context."""
        correlation_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            correlation_id=correlation_id,
            method=request.method,
            path=request.url.path,
        )

        response = await call_next(request)
        response.headers["X-Request-ID"] = correlation_id
        return response
