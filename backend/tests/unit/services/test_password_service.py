"""Unit tests for Argon2id PasswordService."""

from __future__ import annotations

import pytest

from app.domain.exceptions.domain_exceptions import ValidationError
from app.services.auth_service import AuthService
from app.services.password_service import PasswordService


def test_password_hash_and_verify() -> None:
    """Test Argon2id password hashing and successful verification."""
    password = "SuperSecretPassword123!"
    hashed = PasswordService.hash_password(password)

    assert hashed != password
    assert "$argon2id$" in hashed
    assert PasswordService.verify_password(password, hashed) is True
    assert PasswordService.verify_password("WrongPassword123!", hashed) is False


def test_password_strength_validation() -> None:
    """Test password policy enforcement."""
    # Valid password
    AuthService._validate_password_strength("Str0ng#Pass123")

    # Too short
    with pytest.raises(ValidationError, match="at least 8 characters"):
        AuthService._validate_password_strength("Short1!")

    # Missing uppercase
    with pytest.raises(ValidationError, match="at least one uppercase letter"):
        AuthService._validate_password_strength("lowercase123!@#")

    # Missing lowercase
    with pytest.raises(ValidationError, match="at least one lowercase letter"):
        AuthService._validate_password_strength("UPPERCASE123!@#")

    # Missing digit
    with pytest.raises(ValidationError, match="at least one digit"):
        AuthService._validate_password_strength("NoDigitsSpecial!@#")

    # Missing special char
    with pytest.raises(ValidationError, match="at least one special character"):
        AuthService._validate_password_strength("NoSpecialChar123")
