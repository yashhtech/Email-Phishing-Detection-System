"""Production Security Dashboard API router backed by real PostgreSQL aggregations.

Endpoints:
- GET  /api/v1/dashboard/metrics        — Key aggregated metrics
- GET  /api/v1/dashboard/charts         — All 8 production chart datasets
- GET  /api/v1/dashboard/recent-threats — Real-time recent threat items
- WS   /ws/dashboard                    — WebSocket for live analysis completion broadcasts
"""

from __future__ import annotations

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.api.dependencies import get_optional_user_claims, get_uow
from app.api.schemas.dashboard import (
    DashboardChartsResponse,
    DashboardMetricsResponse,
    RecentThreatItem,
)
from app.infrastructure.db.models.organization import Organization
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.infrastructure.websocket.manager import ws_manager
from app.services.token_service import TokenClaims

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


async def _resolve_tenant_id(
    claims: TokenClaims | None,
    uow: UnitOfWork,
) -> uuid.UUID:
    """Resolve tenant ID from JWT claims or fallback to default organization."""
    if claims is not None:
        return claims.org_id

    # Fallback to default demo tenant if unauthenticated
    res = await uow.session.execute(  # type: ignore[union-attr]
        select(Organization).where(Organization.slug == "default-tenant")
    )
    demo_org = res.scalar_one_or_none()
    if demo_org is None:
        demo_org = Organization(
            name="Security Operations Demo",
            slug="default-tenant",
            primary_domain="demo.security.local",
            is_active=True,
        )
        uow.session.add(demo_org)  # type: ignore[union-attr]
        await uow.session.flush()  # type: ignore[union-attr]
    return demo_org.id


@router.get(
    "/metrics",
    response_model=DashboardMetricsResponse,
    summary="Get authoritative security metrics computed from PostgreSQL",
)
async def get_dashboard_metrics(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
) -> DashboardMetricsResponse:
    """Return all 12 key dashboard metrics aggregated in real-time from PostgreSQL."""
    async with uow:
        # If tenant is specified in claims, filter by org_id; otherwise compute platform-wide / demo
        org_id: uuid.UUID | None = claims.org_id if claims else None
        return await uow.dashboard.get_metrics(org_id)


@router.get(
    "/charts",
    response_model=DashboardChartsResponse,
    summary="Get datasets for all 8 production dashboard charts",
)
async def get_dashboard_charts(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
    days: int = Query(default=14, ge=1, le=90, description="Window in days for time series"),
) -> DashboardChartsResponse:
    """Return full datasets for:
    1. Threats over time
    2. Risk distribution
    3. Attack type distribution
    4. Severity distribution
    5. Analysis processing time
    6. LLM usage
    7. Detection trends
    8. Recent threats
    """
    async with uow:
        org_id: uuid.UUID | None = claims.org_id if claims else None
        return await uow.dashboard.get_charts_data(org_id, days=days)


@router.get(
    "/recent-threats",
    response_model=list[RecentThreatItem],
    summary="Get recent threat incidents for forensic table",
)
async def get_recent_threats(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
    limit: int = Query(default=20, ge=1, le=100),
) -> list[RecentThreatItem]:
    """Return the latest malicious and suspicious email threat analyses."""
    async with uow:
        org_id: uuid.UUID | None = claims.org_id if claims else None
        return await uow.dashboard.get_recent_threats(org_id, limit=limit)


# ---------------------------------------------------------------------------
# WebSocket Endpoint for live Dashboard event streaming
# ---------------------------------------------------------------------------


@router.websocket("/ws/dashboard")
async def websocket_dashboard_endpoint(websocket: WebSocket) -> None:
    """Stream live analysis completion and threat events to the dashboard in real-time.

    When any background worker completes an analysis, an event is delivered over this
    WebSocket so the frontend can dynamically update its charts and metric cards without
    refreshing the entire page.
    """
    await ws_manager.connect(websocket, analysis_id=None)
    logger.info("dashboard_websocket_client_connected")
    try:
        await ws_manager.send_personal_message(
            {
                "type": "connected",
                "channel": "dashboard",
                "message": "Subscribed to live security telemetry",
            },
            websocket,
        )

        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket, analysis_id=None)
        logger.info("dashboard_websocket_client_disconnected")
    except Exception as exc:
        logger.debug("dashboard_ws_closed", error=str(exc))
        await ws_manager.disconnect(websocket, analysis_id=None)
