"""Unit tests for domain entities."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.domain.entities.analysis import RiskLevel
from app.domain.entities.email import Email, EmailPriority, EmailStatus
from app.domain.entities.risk import RiskScore
from app.domain.entities.threat import IOCType, ThreatIndicator
from app.domain.entities.user import User, UserRole
from app.domain.exceptions.domain_exceptions import (
    ForbiddenError,
    NotFoundError,
)
from app.domain.value_objects.identifiers import generate_id


def test_generate_id_returns_26_char_string() -> None:
    """ULID must be exactly 26 characters."""
    uid = generate_id()
    assert len(uid) == 26
    assert uid.isalnum()


def test_generate_id_is_unique() -> None:
    """Two generated IDs must be different."""
    assert generate_id() != generate_id()


def test_email_entity_defaults() -> None:
    """Email entity has correct defaults."""
    email = Email(
        id=generate_id(),
        message_id="<test@example.com>",
        from_address="sender@example.com",
        from_domain="example.com",
        received_at=datetime.now(UTC),
    )
    assert email.status == EmailStatus.QUEUED
    assert email.priority == EmailPriority.NORMAL
    assert email.has_attachments is False
    assert email.to_addresses == []


def test_email_entity_is_frozen() -> None:
    """Email entity must be immutable."""
    email = Email(
        id=generate_id(),
        message_id="<test@example.com>",
        from_address="sender@example.com",
        from_domain="example.com",
        received_at=datetime.now(UTC),
    )
    with pytest.raises(ValidationError):
        email.status = EmailStatus.COMPLETE  # type: ignore[misc]


def test_risk_score_bounds() -> None:
    """RiskScore must enforce 0-100 bounds."""
    score = RiskScore(score=85, level=RiskLevel.HIGH)
    assert score.score == 85

    with pytest.raises(ValidationError):
        RiskScore(score=101, level=RiskLevel.CRITICAL)

    with pytest.raises(ValidationError):
        RiskScore(score=-1, level=RiskLevel.SAFE)


def test_threat_indicator_confidence_bounds() -> None:
    """ThreatIndicator confidence must be in [0.0, 1.0]."""
    now = datetime.now(UTC)
    indicator = ThreatIndicator(
        id=generate_id(),
        type=IOCType.DOMAIN,
        value="paypa1.com",
        confidence=0.97,
        first_seen=now,
        last_seen=now,
    )
    assert indicator.confidence == 0.97

    with pytest.raises(ValidationError):
        ThreatIndicator(
            id=generate_id(),
            type=IOCType.DOMAIN,
            value="bad.com",
            confidence=1.5,
            first_seen=now,
            last_seen=now,
        )


def test_not_found_error_http_status() -> None:
    """NotFoundError must have HTTP 404 status."""
    exc = NotFoundError("Email", "eml_abc123")
    assert exc.http_status == 404
    assert exc.code == "NOT_FOUND"
    assert "eml_abc123" in exc.message


def test_forbidden_error_http_status() -> None:
    """ForbiddenError must have HTTP 403 status."""
    exc = ForbiddenError()
    assert exc.http_status == 403
    assert exc.code == "FORBIDDEN"


def test_user_entity_defaults() -> None:
    """User entity has correct defaults."""
    now = datetime.now(UTC)
    user = User(
        id=generate_id(),
        email="analyst@example.com",
        full_name="Test Analyst",
        created_at=now,
        updated_at=now,
    )
    assert user.role == UserRole.VIEWER
    assert user.is_active is True
    assert user.last_login_at is None
