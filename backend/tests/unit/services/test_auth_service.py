"""Unit and domain service tests for AuthService."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.domain.exceptions.domain_exceptions import (
    RateLimitError,
    UnauthorizedError,
)
from app.infrastructure.config.settings import Settings
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization, Role, User, UserRoleType
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.services.auth_service import AuthService
from app.services.password_service import PasswordService
from app.services.token_blocklist_service import TokenBlocklistService
from app.services.token_service import TokenService


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def setex(self, name: str, time: int, value: str) -> bool:
        self.store[name] = value
        return True

    async def exists(self, *names: str) -> int:
        return sum(1 for name in names if name in self.store)

    async def get(self, name: str) -> Any:
        return self.store.get(name)


@pytest.fixture
async def db_session_factory() -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.fixture
def auth_components() -> tuple[AuthService, TokenBlocklistService, TokenService]:
    settings = Settings(
        jwt_secret_key=SecretStr("super_secret_jwt_key_for_testing_12345!!"),
        jwt_algorithm="HS256",
        access_token_expire_minutes=15,
        refresh_token_expire_days=7,
    )
    token_svc = TokenService(settings)
    fake_redis = FakeRedis()
    blocklist_svc = TokenBlocklistService(fake_redis)  # type: ignore[arg-type]
    pwd_svc = PasswordService()
    auth_svc = AuthService(token_svc, blocklist_svc, pwd_svc)
    return auth_svc, blocklist_svc, token_svc


@pytest.mark.asyncio
async def test_auth_service_successful_login_and_logout(
    db_session_factory: async_sessionmaker[AsyncSession],
    auth_components: tuple[AuthService, TokenBlocklistService, TokenService],
) -> None:
    """Test full login, token decoding, and logout revocation."""
    auth_svc, blocklist_svc, token_svc = auth_components

    # Seed Organization and User
    async with UnitOfWork(db_session_factory) as uow:
        org = Organization(name="CyberSec Corp", slug="cybersec-corp")
        await uow.organizations.create(org)

        role = Role(name="Security Analyst", role_type=UserRoleType.SECURITY_ANALYST)
        uow.session.add(role)
        await uow.session.flush()

        plain_pwd = "CorrectHorseBatteryStaple123!"
        user = User(
            org_id=org.id,
            role_id=role.id,
            email="analyst@cybersec.com",
            full_name="Sarah Connor",
            hashed_password=PasswordService.hash_password(plain_pwd),
            is_active=True,
        )
        await uow.users.create(user)

    # Perform login
    token_pair = await auth_svc.login(
        "analyst@cybersec.com",
        plain_pwd,
        UnitOfWork(db_session_factory),
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0",
    )

    assert token_pair.access_token is not None
    assert token_pair.refresh_token is not None
    assert token_pair.user.email == "analyst@cybersec.com"

    # Decode access token
    claims = token_svc.decode_token(token_pair.access_token, expected_type="access")
    assert claims.user_id == user.id
    assert claims.role == UserRoleType.SECURITY_ANALYST.value

    # Refresh token rotation
    refreshed_pair = await auth_svc.refresh(
        token_pair.refresh_token,
        UnitOfWork(db_session_factory),
    )
    assert refreshed_pair.access_token is not None
    assert refreshed_pair.refresh_token != token_pair.refresh_token

    # Verify old refresh token JTI was revoked
    old_claims = token_svc.decode_token(token_pair.refresh_token, expected_type="refresh")
    assert await blocklist_svc.is_revoked(old_claims.jti) is True

    # Logout
    await auth_svc.logout(
        refreshed_pair.refresh_token,
        UnitOfWork(db_session_factory),
        user.id,
    )
    new_claims = token_svc.decode_token(refreshed_pair.refresh_token, expected_type="refresh")
    assert await blocklist_svc.is_revoked(new_claims.jti) is True


@pytest.mark.asyncio
async def test_auth_service_brute_force_lockout(
    db_session_factory: async_sessionmaker[AsyncSession],
    auth_components: tuple[AuthService, TokenBlocklistService, TokenService],
) -> None:
    """Ensure account locks after repeated failed attempts."""
    auth_svc, _, _ = auth_components

    async with UnitOfWork(db_session_factory) as uow:
        org = Organization(name="Target Corp", slug="target-corp")
        await uow.organizations.create(org)

        role = Role(name="User Role", role_type=UserRoleType.USER)
        uow.session.add(role)
        await uow.session.flush()

        user = User(
            org_id=org.id,
            role_id=role.id,
            email="victim@target.com",
            full_name="Alice Smith",
            hashed_password=PasswordService.hash_password("RealSecret99!"),
            is_active=True,
        )
        await uow.users.create(user)

    # 4 failed attempts should raise UnauthorizedError
    for _ in range(4):
        with pytest.raises(UnauthorizedError, match="Invalid credentials"):
            await auth_svc.login(
                "victim@target.com", "WrongPassword1!", UnitOfWork(db_session_factory)
            )

    # 5th attempt hits the threshold and raises RateLimitError
    with pytest.raises(RateLimitError, match="Too many failed attempts"):
        await auth_svc.login("victim@target.com", "WrongPassword1!", UnitOfWork(db_session_factory))

    # Subsequent attempts while locked also raise RateLimitError
    with pytest.raises(RateLimitError, match="Account locked"):
        await auth_svc.login("victim@target.com", "RealSecret99!", UnitOfWork(db_session_factory))


@pytest.mark.asyncio
async def test_auth_service_change_password_and_revocation(
    db_session_factory: async_sessionmaker[AsyncSession],
    auth_components: tuple[AuthService, TokenBlocklistService, TokenService],
) -> None:
    """Password change validates old password, sets new hash, and revokes tokens."""
    auth_svc, blocklist_svc, _ = auth_components

    async with UnitOfWork(db_session_factory) as uow:
        org = Organization(name="ACME", slug="acme")
        await uow.organizations.create(org)

        role = Role(name="Admin", role_type=UserRoleType.ADMIN)
        uow.session.add(role)
        await uow.session.flush()

        old_pwd = "OldPassword123!"
        user = User(
            org_id=org.id,
            role_id=role.id,
            email="admin@acme.com",
            full_name="Root Admin",
            hashed_password=PasswordService.hash_password(old_pwd),
            is_active=True,
        )
        await uow.users.create(user)

    new_pwd = "BrandNewSecretPassword456$"
    await auth_svc.change_password(
        user.id,
        old_pwd,
        new_pwd,
        UnitOfWork(db_session_factory),
    )

    # Check user-level revocation marker was set
    ts = await blocklist_svc.get_user_revocation_timestamp(user.id)
    assert ts is not None

    # Old password no longer works
    with pytest.raises(UnauthorizedError, match="Invalid credentials"):
        await auth_svc.login("admin@acme.com", old_pwd, UnitOfWork(db_session_factory))

    # New password works
    pair = await auth_svc.login("admin@acme.com", new_pwd, UnitOfWork(db_session_factory))
    assert pair.access_token is not None
