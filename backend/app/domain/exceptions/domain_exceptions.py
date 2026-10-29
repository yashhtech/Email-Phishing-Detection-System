"""Domain-layer exception hierarchy.

Domain exceptions are pure Python — no HTTP status codes here.
The API layer maps these to appropriate HTTP responses.
"""

from __future__ import annotations


class DomainException(Exception):
    """Base class for all domain exceptions."""

    def __init__(
        self,
        message: str,
        code: str = "DOMAIN_ERROR",
        http_status: int = 500,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.http_status = http_status


class NotFoundError(DomainException):
    """Resource does not exist."""

    def __init__(self, resource: str, resource_id: str) -> None:
        super().__init__(
            message=f"{resource} '{resource_id}' not found",
            code="NOT_FOUND",
            http_status=404,
        )


class ConflictError(DomainException):
    """Resource already exists (duplicate)."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="CONFLICT", http_status=409)


class ValidationError(DomainException):
    """Domain-level validation failure."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="VALIDATION_ERROR", http_status=400)


class UnauthorizedError(DomainException):
    """Authentication required or failed."""

    def __init__(self, message: str = "Authentication required") -> None:
        super().__init__(message=message, code="UNAUTHORIZED", http_status=401)


class ForbiddenError(DomainException):
    """Authenticated but insufficient permissions."""

    def __init__(self, message: str = "Insufficient permissions") -> None:
        super().__init__(message=message, code="FORBIDDEN", http_status=403)


class RateLimitError(DomainException):
    """Rate limit exceeded."""

    def __init__(self, message: str = "Rate limit exceeded") -> None:
        super().__init__(message=message, code="RATE_LIMITED", http_status=429)


class AnalysisError(DomainException):
    """Analysis pipeline failure."""

    def __init__(self, message: str, email_id: str) -> None:
        super().__init__(
            message=f"Analysis failed for email '{email_id}': {message}",
            code="ANALYSIS_ERROR",
            http_status=500,
        )


class ExternalServiceError(DomainException):
    """External provider (Groq, VirusTotal, etc.) failure."""

    def __init__(self, service: str, message: str) -> None:
        super().__init__(
            message=f"External service '{service}' failed: {message}",
            code="EXTERNAL_SERVICE_ERROR",
            http_status=503,
        )
