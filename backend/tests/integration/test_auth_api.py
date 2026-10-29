"""Integration tests for Authentication & Authorization API endpoints and RBAC."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.dependencies import (
    get_blocklist_service,
    get_db,
    get_token_service,
    get_uow,
    rate_limit_login,
    rate_limit_register,
)
from app.infrastructure.config.settings import Settings, get_settings
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization, Role, User, UserRoleType
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.main import create_app
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

    async def incr(self, key: str) -> int:
        val = int(self.store.get(key, 0)) + 1
        self.store[key] = str(val)
        return val

    async def expire(self, key: str, seconds: int) -> bool:
        return True


@pytest_asyncio.fixture
async def test_env() -> AsyncGenerator[dict[str, Any], None]:
    """Setup in-memory SQLite DB, fake Redis, seed roles and org, and configure app overrides."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    fake_redis = FakeRedis()
    blocklist_service = TokenBlocklistService(fake_redis)  # type: ignore[arg-type]

    test_settings = Settings(
        jwt_secret_key=SecretStr("test_jwt_secret_key_long_enough_32_bytes!"),
        jwt_algorithm="HS256",
        access_token_expire_minutes=15,
        refresh_token_expire_days=7,
        app_env="development",
    )
    token_service = TokenService(test_settings)

    # Seed roles and organizations
    async with session_factory() as session:
        org = Organization(name="SecOps Defense", slug="secops-defense")
        session.add(org)

        roles: dict[UserRoleType, Role] = {}
        for r_type in [
            UserRoleType.VIEWER,
            UserRoleType.USER,
            UserRoleType.SECURITY_ANALYST,
            UserRoleType.ADMIN,
        ]:
            role = Role(
                name=r_type.value.capitalize(), role_type=r_type, permissions=[r_type.value]
            )
            session.add(role)
            roles[r_type] = role

        await session.flush()

        # Seed 4 users across the 4 roles
        users: dict[UserRoleType, User] = {}
        pwd_hash = PasswordService.hash_password("ComplexSecret123!")

        for r_type, role in roles.items():
            u = User(
                org_id=org.id,
                role_id=role.id,
                email=f"{r_type.value}@secops.com",
                full_name=f"{r_type.value.title()} User",
                hashed_password=pwd_hash,
                is_active=True,
            )
            session.add(u)
            users[r_type] = u

        await session.commit()
        org_id = org.id

    app = create_app()

    # Dependency overrides
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as s:
            yield s

    def override_get_uow() -> UnitOfWork:
        return UnitOfWork(session_factory)

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_uow] = override_get_uow
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.dependency_overrides[get_token_service] = lambda: token_service
    app.dependency_overrides[get_blocklist_service] = lambda: blocklist_service
    app.dependency_overrides[rate_limit_login] = lambda: None
    app.dependency_overrides[rate_limit_register] = lambda: None

    yield {
        "app": app,
        "token_service": token_service,
        "org_id": org_id,
        "users": users,
        "password": "ComplexSecret123!",
    }

    await engine.dispose()


@pytest.mark.asyncio
async def test_auth_login_success(test_env: dict[str, Any]) -> None:
    """Test successful login returns access and refresh tokens, without exposing password."""
    app = test_env["app"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@secops.com", "password": test_env["password"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == "admin@secops.com"
        assert "password" not in str(data)
        assert "hashed_password" not in str(data)

        # Check security headers
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"


@pytest.mark.asyncio
async def test_auth_login_invalid_password(test_env: dict[str, Any]) -> None:
    """Test invalid password returns 401."""
    app = test_env["app"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@secops.com", "password": "WrongPassword999!"},
        )
        assert resp.status_code == 401
        data = resp.json()
        assert data["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_auth_refresh_and_logout_flow(test_env: dict[str, Any]) -> None:
    """Test refresh rotation and subsequent logout revocation."""
    app = test_env["app"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Login
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "user@secops.com", "password": test_env["password"]},
        )
        tokens = login_resp.json()
        old_refresh = tokens["refresh_token"]

        # Refresh
        refresh_resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        assert refresh_resp.status_code == 200
        new_tokens = refresh_resp.json()
        new_refresh = new_tokens["refresh_token"]
        assert new_refresh != old_refresh

        # Using old refresh token now fails (revoked by rotation)
        reused_resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        assert reused_resp.status_code == 401

        # Logout with new refresh token
        logout_resp = await client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": new_refresh},
            headers={"Authorization": f"Bearer {new_tokens['access_token']}"},
        )
        assert logout_resp.status_code == 200

        # After logout, new refresh token is revoked
        after_logout = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": new_refresh},
        )
        assert after_logout.status_code == 401


@pytest.mark.asyncio
async def test_auth_me_profile(test_env: dict[str, Any]) -> None:
    """Test GET /auth/me returns current user details with valid token, 401 without."""
    app = test_env["app"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Unauthenticated
        unauth_resp = await client.get("/api/v1/auth/me")
        assert unauth_resp.status_code == 401

        # Authenticate
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "security_analyst@secops.com", "password": test_env["password"]},
        )
        access_token = login_resp.json()["access_token"]

        # Authenticated
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "security_analyst@secops.com"
        assert data["role"] == "security_analyst"


@pytest.mark.asyncio
async def test_rbac_access_control_on_users_endpoints(test_env: dict[str, Any]) -> None:
    """Verify RBAC role hierarchy on /users endpoints.

    VIEWER and USER: 403 Forbidden to list users.
    SECURITY_ANALYST and ADMIN: 200 OK to list users.
    SECURITY_ANALYST: 403 Forbidden to update or delete users.
    ADMIN: 200 OK to update users, 204 to delete other users.
    """
    app = test_env["app"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Obtain access tokens for VIEWER, ANALYST, and ADMIN
        tokens: dict[str, str] = {}
        for role_name in ["viewer", "security_analyst", "admin"]:
            r = await client.post(
                "/api/v1/auth/login",
                json={"email": f"{role_name}@secops.com", "password": test_env["password"]},
            )
            tokens[role_name] = r.json()["access_token"]

        # 1. VIEWER cannot list users (requires ANALYST+)
        viewer_list = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {tokens['viewer']}"},
        )
        assert viewer_list.status_code == 403

        # 2. SECURITY_ANALYST can list users
        analyst_list = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {tokens['security_analyst']}"},
        )
        assert analyst_list.status_code == 200
        assert analyst_list.json()["total"] >= 4

        # 3. Target user ID to modify
        target_user = test_env["users"][UserRoleType.VIEWER]
        target_id = str(target_user.id)

        # 4. SECURITY_ANALYST cannot modify users (requires ADMIN)
        analyst_update = await client.patch(
            f"/api/v1/users/{target_id}",
            json={"full_name": "New Name By Analyst"},
            headers={"Authorization": f"Bearer {tokens['security_analyst']}"},
        )
        assert analyst_update.status_code == 403

        # 5. ADMIN can modify users
        admin_update = await client.patch(
            f"/api/v1/users/{target_id}",
            json={"full_name": "Updated Name By Admin"},
            headers={"Authorization": f"Bearer {tokens['admin']}"},
        )
        assert admin_update.status_code == 200
        assert admin_update.json()["full_name"] == "Updated Name By Admin"

        # 6. ADMIN cannot delete themselves
        admin_user = test_env["users"][UserRoleType.ADMIN]
        self_del = await client.delete(
            f"/api/v1/users/{admin_user.id}",
            headers={"Authorization": f"Bearer {tokens['admin']}"},
        )
        assert self_del.status_code == 403

        # 7. ADMIN can delete another user
        del_resp = await client.delete(
            f"/api/v1/users/{target_id}",
            headers={"Authorization": f"Bearer {tokens['admin']}"},
        )
        assert del_resp.status_code == 204
