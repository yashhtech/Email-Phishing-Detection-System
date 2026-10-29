"""Unit tests for the paginated Analysis History API and server-side filtering."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient

from app.api.dependencies import get_uow
from app.api.schemas.history import AnalysisHistoryItem, AnalysisHistoryResponse
from app.main import app


class TestHistorySchemas:
    """Validate Pydantic models for Analysis History API."""

    def test_history_item_validation(self) -> None:
        item = AnalysisHistoryItem(
            analysis_id=str(uuid.uuid4()),
            email_id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            sender="attacker@phishing-target.com",
            sender_domain="phishing-target.com",
            subject="Urgent account update required",
            classification="malicious",
            severity="critical",
            risk_score=95,
            status="completed",
            attack_type="credential_harvesting",
            duration_ms=1200,
        )
        assert item.risk_score == 95
        assert item.severity == "critical"
        assert item.classification == "malicious"

    def test_history_response_defaults(self) -> None:
        resp = AnalysisHistoryResponse(
            items=[],
            total_count=0,
            page=1,
            page_size=20,
            total_pages=1,
            has_next=False,
            has_prev=False,
        )
        assert resp.total_count == 0
        assert resp.items == []
        assert resp.has_next is False
        assert resp.has_prev is False


@pytest.mark.asyncio
class TestAnalysisHistoryAPI:
    """Validate GET /analysis/history endpoint behavior."""

    async def test_get_history_empty_state(self, async_client: AsyncClient) -> None:
        fake_uow = MagicMock()
        fake_analyses = MagicMock()
        fake_analyses.get_paginated_history = AsyncMock(return_value=([], 0))
        fake_uow.analyses = fake_analyses

        # Mock tenant resolution
        fake_org = MagicMock()
        fake_org.id = uuid.uuid4()
        fake_session = AsyncMock()
        fake_result = MagicMock()
        fake_result.scalar_one_or_none.return_value = fake_org
        fake_session.execute = AsyncMock(return_value=fake_result)
        fake_uow.session = fake_session
        fake_uow.__aenter__ = AsyncMock(return_value=fake_uow)
        fake_uow.__aexit__ = AsyncMock(return_value=None)

        app.dependency_overrides[get_uow] = lambda: fake_uow

        try:
            res = await async_client.get("/api/v1/analysis/history?page=1&page_size=20")
            assert res.status_code == 200
            data = res.json()
            assert data["total_count"] == 0
            assert data["items"] == []
            assert data["page"] == 1
            assert data["total_pages"] == 1
            assert data["has_next"] is False
            assert data["has_prev"] is False
        finally:
            app.dependency_overrides.clear()

    async def test_get_history_with_items_and_filtering(self, async_client: AsyncClient) -> None:
        fake_uow = MagicMock()
        fake_analyses = MagicMock()

        mock_item = {
            "analysis_id": str(uuid.uuid4()),
            "email_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC),
            "sender": "finance@fraud-domain.com",
            "sender_domain": "fraud-domain.com",
            "subject": "Wire Transfer Instruction",
            "classification": "malicious",
            "severity": "high",
            "risk_score": 82,
            "status": "completed",
            "attack_type": "bec",
            "duration_ms": 2300,
        }
        fake_analyses.get_paginated_history = AsyncMock(return_value=([mock_item], 1))
        fake_uow.analyses = fake_analyses

        fake_org = MagicMock()
        fake_org.id = uuid.uuid4()
        fake_session = AsyncMock()
        fake_result = MagicMock()
        fake_result.scalar_one_or_none.return_value = fake_org
        fake_session.execute = AsyncMock(return_value=fake_result)
        fake_uow.session = fake_session
        fake_uow.__aenter__ = AsyncMock(return_value=fake_uow)
        fake_uow.__aexit__ = AsyncMock(return_value=None)

        app.dependency_overrides[get_uow] = lambda: fake_uow

        try:
            res = await async_client.get(
                "/api/v1/analysis/history"
                "?page=1&page_size=20&severity=high&attack_type=bec&min_risk=80&search=wire"
            )
            assert res.status_code == 200
            data = res.json()
            assert data["total_count"] == 1
            assert len(data["items"]) == 1
            assert data["items"][0]["sender"] == "finance@fraud-domain.com"
            assert data["items"][0]["attack_type"] == "bec"
            assert data["items"][0]["risk_score"] == 82
        finally:
            app.dependency_overrides.clear()
