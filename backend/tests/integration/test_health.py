"""Integration tests for the health check endpoint."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint_returns_expected_structure(async_client: AsyncClient) -> None:
    """Health endpoint returns correct JSON structure."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code in (200, 503)
    data = response.json()
    assert "status" in data
    assert "checks" in data
    assert "version" in data
    assert "timestamp" in data
    assert "database" in data["checks"]
    assert "redis" in data["checks"]
