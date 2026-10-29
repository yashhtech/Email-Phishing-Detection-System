"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from app.infrastructure.config.settings import Settings, get_settings
from app.main import app


def get_test_settings() -> Settings:
    """Override settings for the test environment."""
    return Settings(
        app_env="development",
        database_url="postgresql+asyncpg://postgres:postgres@localhost:5432/email_threat_test",
        redis_url="redis://localhost:6379/15",
        log_level="WARNING",
        debug=False,
    )


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Session-scoped test settings."""
    return get_test_settings()


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP test client for integration tests."""
    app.dependency_overrides[get_settings] = get_test_settings
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client
    app.dependency_overrides.clear()
