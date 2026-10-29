"""Common API response envelope schemas."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Generic, TypeVar
from uuid import uuid4

from pydantic import BaseModel, Field

T = TypeVar("T")


class ResponseMeta(BaseModel):
    """Metadata included in every API response."""

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    version: str = Field(default="v1")


class ApiResponse(BaseModel, Generic[T]):
    """Standard success response envelope."""

    success: bool = Field(default=True)
    data: T
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


class PaginationMeta(BaseModel):
    """Pagination metadata for list responses."""

    cursor_next: str | None = Field(default=None)
    cursor_prev: str | None = Field(default=None)
    has_next: bool = Field(default=False)
    has_prev: bool = Field(default=False)
    total_count: int = Field(ge=0)


class PaginatedApiResponse(BaseModel, Generic[T]):
    """Standard paginated list response envelope."""

    success: bool = Field(default=True)
    data: list[T]
    meta: ResponseMeta = Field(default_factory=ResponseMeta)
    pagination: PaginationMeta
