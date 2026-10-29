"""Timing middleware — adds X-Response-Time-Ms to all responses.

Helps identify slow endpoints via response headers without requiring
external APM tooling.
"""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class ResponseTimingMiddleware(BaseHTTPMiddleware):
    """Measures total wall-clock API latency and appends it to response headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        t0 = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.2f}"
        return response
