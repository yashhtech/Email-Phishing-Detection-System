"""Global exception handlers that map domain exceptions to HTTP responses."""

from __future__ import annotations

import structlog
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError

from app.domain.exceptions.domain_exceptions import DomainException

logger = structlog.get_logger(__name__)


def _error_response(code: str, message: str, status_code: int) -> JSONResponse:
    """Build a standardised error JSON response."""
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error": {
                "code": code,
                "message": message,
            },
        },
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register all global exception handlers on the FastAPI application."""

    @app.exception_handler(DomainException)
    async def domain_exception_handler(request: Request, exc: DomainException) -> JSONResponse:
        """Map domain exceptions to structured HTTP responses."""
        if exc.http_status >= 500:
            logger.error(
                "domain_exception",
                code=exc.code,
                message=exc.message,
                path=str(request.url),
            )
        return _error_response(exc.code, exc.message, exc.http_status)

    @app.exception_handler(PydanticValidationError)
    async def pydantic_validation_handler(
        request: Request, exc: PydanticValidationError
    ) -> JSONResponse:
        """Map Pydantic validation errors to 422 responses with sanitized details."""
        # Only expose field location and message — not internal types or URLs
        sanitized = [
            {
                "field": " → ".join(str(loc) for loc in err.get("loc", [])),
                "message": err.get("msg", "Validation error"),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "success": False,
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Request validation failed",
                    "details": sanitized,
                },
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Catch-all handler — logs full traceback, returns opaque 500."""
        logger.exception(
            "unhandled_exception",
            exc_type=type(exc).__name__,
            path=str(request.url),
        )
        return _error_response(
            "INTERNAL_ERROR",
            "An unexpected error occurred. Please try again later.",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
