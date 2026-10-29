"""Integration tests for Email Analyzer endpoints."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.dependencies import get_db, get_uow
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.main import create_app


@pytest_asyncio.fixture
async def email_test_env() -> AsyncGenerator[dict[str, Any], None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with session_factory() as session:
        org = Organization(
            name="Security Operations Demo",
            slug="default-tenant",
            primary_domain="demo.security.local",
            is_active=True,
        )
        session.add(org)
        await session.commit()
        org_id = org.id

    app = create_app()

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as s:
            yield s

    def override_get_uow() -> UnitOfWork:
        return UnitOfWork(session_factory)

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_uow] = override_get_uow

    yield {"app": app, "org_id": org_id}
    await engine.dispose()


@pytest.mark.asyncio
async def test_analyze_structured_email_clean(email_test_env: dict[str, Any]) -> None:
    app = email_test_env["app"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "from_address": "notifications@legit-company.com",
            "to_addresses": ["employee@target.com"],
            "cc_addresses": [],
            "reply_to": None,
            "subject": "Monthly Engineering Summary",
            "body_plain": "Here is the summary of this month's sprints: https://internal.company.com/wiki",
            "body_html": None,
            "raw_headers": "Authentication-Results: spf=pass dkim=pass dmarc=pass",
        }

        resp = await client.post("/api/v1/emails/analyze", json=payload)
        assert resp.status_code == 200, resp.text
        data = resp.json()

        assert data["from_address"] == "notifications@legit-company.com"
        assert data["from_domain"] == "legit-company.com"
        assert data["subject"] == "Monthly Engineering Summary"
        assert data["verdict"] == "clean"
        assert data["initial_risk_score"] == 0.0
        assert data["initial_risk_level"] == "safe"
        assert len(data["urls"]) == 1
        assert data["urls"][0]["defanged_url"] == "hxxps://internal[.]company[.]com/wiki"
        assert data["headers"]["spf_status"] == "pass"


@pytest.mark.asyncio
async def test_analyze_raw_email_phishing_detection(email_test_env: dict[str, Any]) -> None:
    app = email_test_env["app"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        raw_content = (
            'From: "PayPal Support" <billing@paypa1-service.top>\n'
            "To: victim@company.com\n"
            "Reply-To: phisher@harvest-creds.com\n"
            "Subject: CRITICAL: Immediate Account Verification Required\n"
            "Authentication-Results: spf=fail dkim=fail dmarc=fail\n"
            "\n"
            "Please click here immediately: http://185.220.101.5/login to verify your credentials.\n"
        )

        resp = await client.post("/api/v1/emails/analyze/raw", json={"raw_content": raw_content})
        assert resp.status_code == 200, resp.text
        data = resp.json()

        assert data["verdict"] in ("malicious", "suspicious")
        assert data["initial_risk_score"] >= 50.0
        assert data["from_domain"] == "paypa1-service.top"
        assert data["headers"]["spf_status"] == "fail"
        assert data["headers"]["dkim_status"] == "fail"
        assert data["headers"]["dmarc_status"] == "fail"

        # Check threat signals
        assert len(data["threat_signals"]) >= 3

        # Test retrieval by ID
        email_id = data["email_id"]
        get_resp = await client.get(f"/api/v1/emails/{email_id}")
        assert get_resp.status_code == 200
        get_data = get_resp.json()
        assert get_data["email_id"] == email_id
        assert get_data["from_domain"] == "paypa1-service.top"


@pytest.mark.asyncio
async def test_analyze_upload_eml_file(email_test_env: dict[str, Any]) -> None:
    app = email_test_env["app"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        eml_bytes = (
            b"From: alerts@bank.com\n"
            b"To: user@target.com\n"
            b"Subject: Security Update\n"
            b"Authentication-Results: spf=pass dkim=pass dmarc=pass\n"
            b"\n"
            b"Your account is up to date.\n"
        )
        files = {
            "eml_file": ("test_message.eml", eml_bytes, "message/rfc822"),
        }

        resp = await client.post("/api/v1/emails/analyze/upload", files=files)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["from_address"] == "alerts@bank.com"
        assert data["subject"] == "Security Update"
        assert data["status"] == "complete"
