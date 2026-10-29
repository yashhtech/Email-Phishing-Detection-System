"""Unit tests for TokenBlocklistService using a lightweight in-memory fake Redis."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.services.token_blocklist_service import TokenBlocklistService


class FakeRedis:
    """In-memory dictionary simulating Redis commands used by TokenBlocklistService."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def setex(self, name: str, time: int, value: str) -> bool:
        self.store[name] = value
        return True

    async def exists(self, *names: str) -> int:
        return sum(1 for name in names if name in self.store)

    async def get(self, name: str) -> Any:
        return self.store.get(name)


@pytest.mark.asyncio
async def test_token_blocklist_revocation() -> None:
    """Test revoking a token by JTI and verifying is_revoked."""
    fake_redis = FakeRedis()
    service = TokenBlocklistService(fake_redis)  # type: ignore[arg-type]

    jti = uuid.uuid4()
    assert await service.is_revoked(jti) is False

    await service.revoke(jti, ttl_seconds=3600)
    assert await service.is_revoked(jti) is True


@pytest.mark.asyncio
async def test_token_blocklist_user_wide_revocation() -> None:
    """Test revoking all tokens for a user after security events."""
    fake_redis = FakeRedis()
    service = TokenBlocklistService(fake_redis)  # type: ignore[arg-type]

    user_id = uuid.uuid4()
    assert await service.get_user_revocation_timestamp(user_id) is None

    await service.revoke_all_for_user(user_id, ttl_seconds=86400)
    ts = await service.get_user_revocation_timestamp(user_id)
    assert ts is not None
    assert ts > 0
