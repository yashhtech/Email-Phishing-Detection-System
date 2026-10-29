"""Unit tests for JWT TokenService."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from app.infrastructure.config.settings import Settings
from app.infrastructure.db.models.enums import UserRoleType
from app.services.token_service import TokenService


@pytest.fixture
def token_service() -> TokenService:
    settings = Settings(
        jwt_secret_key=SecretStr("test_jwt_secret_key_at_least_32_bytes_long!!"),
        jwt_algorithm="HS256",
        access_token_expire_minutes=15,
        refresh_token_expire_days=7,
    )
    return TokenService(settings)


def test_create_and_decode_access_token(token_service: TokenService) -> None:
    """Validate access token generation and claims unpacking."""
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    role = UserRoleType.SECURITY_ANALYST.value

    token, jti, exp = token_service.create_access_token(user_id, role, org_id)

    assert isinstance(token, str)
    assert isinstance(jti, uuid.UUID)
    assert exp > datetime.now(UTC)

    claims = token_service.decode_token(token, expected_type="access")
    assert claims.user_id == user_id
    assert claims.org_id == org_id
    assert claims.role == role
    assert claims.jti == jti
    assert claims.token_type == "access"
    assert claims.is_expired() is False


def test_create_and_decode_refresh_token(token_service: TokenService) -> None:
    """Validate refresh token creation and decode with expected_type="refresh"."""
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    role = UserRoleType.USER.value

    token, _jti, _exp = token_service.create_refresh_token(user_id, role, org_id)

    assert isinstance(token, str)
    claims = token_service.decode_token(token, expected_type="refresh")
    assert claims.token_type == "refresh"
    assert claims.user_id == user_id


def test_decode_wrong_token_type(token_service: TokenService) -> None:
    """A refresh token passed to access endpoint should fail."""
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    token, _, _ = token_service.create_refresh_token(user_id, "user", org_id)

    with pytest.raises(ValueError, match="Wrong token type"):
        token_service.decode_token(token, expected_type="access")


def test_tampered_token(token_service: TokenService) -> None:
    """Tampered token fails verification."""
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    token, _, _ = token_service.create_access_token(user_id, "admin", org_id)

    tampered = token[:-4] + "fake"
    with pytest.raises(ValueError, match="Invalid token"):
        token_service.decode_token(tampered, expected_type="access")


def test_expired_token() -> None:
    """Token with 0 or negative TTL reports expired."""
    settings = Settings(
        jwt_secret_key=SecretStr("test_jwt_secret_key_at_least_32_bytes_long!!"),
        jwt_algorithm="HS256",
        access_token_expire_minutes=5,
    )
    svc = TokenService(settings)
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()

    # Create token manually with negative delta
    token, _jti, _exp = svc._create_token(
        user_id, "admin", org_id, "access", timedelta(seconds=-10)
    )
    with pytest.raises(ValueError, match="Signature has expired"):
        svc.decode_token(token, expected_type="access")
