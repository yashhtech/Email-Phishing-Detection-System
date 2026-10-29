"""Threat Intelligence API — lists threat signals and indicators from analyzed emails."""

from __future__ import annotations

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.dependencies import get_optional_user_claims, get_uow
from app.infrastructure.db.models.analysis import Analysis, ThreatSignal
from app.infrastructure.db.models.enums import AttackType, ThreatSeverity
from app.infrastructure.db.models.organization import Organization
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.services.token_service import TokenClaims

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/threats", tags=["Threat Intelligence"])


async def _resolve_tenant_id(
    claims: TokenClaims | None,
    uow: UnitOfWork,
) -> uuid.UUID:
    from sqlalchemy import select as _select

    if claims is not None:
        return claims.org_id
    res = await uow.session.execute(
        _select(Organization).where(Organization.slug == "default-tenant")
    )
    demo_org = res.scalar_one_or_none()
    if demo_org is None:
        demo_org = Organization(
            name="Security Operations Demo",
            slug="default-tenant",
            primary_domain="demo.security.local",
            is_active=True,
        )
        uow.session.add(demo_org)
        await uow.session.flush()
    return demo_org.id


class ThreatSignalItem(BaseModel):
    id: str
    analysis_id: str
    signal_type: str
    category: str
    severity: str
    attack_type: str
    confidence: float
    source: str
    title: str
    description: str
    indicator_value: str | None
    created_at: str


class ThreatsListResponse(BaseModel):
    items: list[ThreatSignalItem]
    total: int
    page: int
    page_size: int
    severity_counts: dict[str, int]
    attack_type_counts: dict[str, int]


@router.get(
    "",
    response_model=ThreatsListResponse,
    summary="List threat signals from analyzed emails",
)
async def list_threats(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)],
    severity: str | None = Query(
        default=None,
        description="Filter by severity: critical|high|medium|low",
    ),
    attack_type: str | None = Query(
        default=None,
        description="Filter by attack type",
    ),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> ThreatsListResponse:
    """Return paginated threat signals with severity/attack_type counts."""
    async with uow:
        org_id = await _resolve_tenant_id(claims, uow)

        # Base query — join to Analysis to get org_id filter
        base = (
            select(ThreatSignal)
            .join(Analysis, ThreatSignal.analysis_id == Analysis.id)
            .where(Analysis.org_id == org_id)
        )

        if severity:
            try:
                sev_enum = ThreatSeverity(severity)
                base = base.where(ThreatSignal.severity == sev_enum)
            except ValueError:
                pass

        if attack_type:
            try:
                at_enum = AttackType(attack_type)
                base = base.where(ThreatSignal.attack_type == at_enum)
            except ValueError:
                pass

        # Count total
        count_stmt = select(func.count()).select_from(base.subquery())
        total_result = await uow.session.execute(count_stmt)
        total = total_result.scalar_one() or 0

        # Paginated results, newest first
        offset = (page - 1) * page_size
        paged = (
            base.order_by(ThreatSignal.created_at.desc())
            .limit(page_size)
            .offset(offset)
        )
        signals_result = await uow.session.execute(paged)
        signals = signals_result.scalars().all()

        # Severity counts
        sev_count_stmt = (
            select(ThreatSignal.severity, func.count(ThreatSignal.id))
            .join(Analysis, ThreatSignal.analysis_id == Analysis.id)
            .where(Analysis.org_id == org_id)
            .group_by(ThreatSignal.severity)
        )
        sev_result = await uow.session.execute(sev_count_stmt)
        severity_counts = {
            (row[0].value if hasattr(row[0], "value") else str(row[0])): row[1]
            for row in sev_result.all()
        }

        # Attack type counts
        at_count_stmt = (
            select(ThreatSignal.attack_type, func.count(ThreatSignal.id))
            .join(Analysis, ThreatSignal.analysis_id == Analysis.id)
            .where(Analysis.org_id == org_id)
            .group_by(ThreatSignal.attack_type)
        )
        at_result = await uow.session.execute(at_count_stmt)
        attack_type_counts = {
            (row[0].value if hasattr(row[0], "value") else str(row[0])): row[1]
            for row in at_result.all()
        }

        items = [
            ThreatSignalItem(
                id=str(sig.id),
                analysis_id=str(sig.analysis_id),
                signal_type=sig.signal_type,
                category=(
                    sig.category.value
                    if hasattr(sig.category, "value")
                    else str(sig.category)
                ),
                severity=(
                    sig.severity.value
                    if hasattr(sig.severity, "value")
                    else str(sig.severity)
                ),
                attack_type=(
                    sig.attack_type.value
                    if hasattr(sig.attack_type, "value")
                    else str(sig.attack_type)
                ),
                confidence=float(sig.confidence),
                source=sig.source_engine,
                title=sig.title,
                description=sig.description or "",
                indicator_value=sig.indicator_value,
                created_at=sig.created_at.isoformat() if sig.created_at else "",
            )
            for sig in signals
        ]

        return ThreatsListResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            severity_counts=severity_counts,
            attack_type_counts=attack_type_counts,
        )
