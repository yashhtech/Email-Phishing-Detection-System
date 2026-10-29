"""Common DTO definitions shared across use cases."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginatedResult(BaseModel, Generic[T]):
    """Generic paginated result container."""

    items: list[T]
    cursor_next: str | None = Field(default=None)
    has_next: bool = Field(default=False)
    total_count: int = Field(ge=0)
