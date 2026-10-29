"""Security Analytics API router backed by PostgreSQL aggregations.

Endpoints:
- GET /api/v1/analytics/overview — Comprehensive analytics overview and telemetry
- GET /api/v1/analytics/export   — Streaming CSV export of threat metrics and trends
"""

from __future__ import annotations

import csv
import io
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse

from app.api.dependencies import get_optional_user_claims, get_uow
from app.api.schemas.analytics import AnalyticsOverviewResponse
from app.infrastructure.cache.response_cache import analytics_cache
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.services.token_service import TokenClaims

router = APIRouter(prefix="/analytics", tags=["Analytics"])

ALLOWED_PRESETS = {"24h", "7d", "30d", "90d"}


def _validate_date_params(
    preset: str | None,
    start: datetime | None,
    end: datetime | None,
) -> None:
    """Validate query parameters for analytics date ranges."""
    if preset is not None and preset not in ALLOWED_PRESETS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid preset '{preset}'. Allowed values: {', '.join(sorted(ALLOWED_PRESETS))}.",
        )
    if start is not None and end is not None and start > end:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Start date must be earlier than or equal to end date.",
        )


async def _generate_analytics_csv(
    overview: AnalyticsOverviewResponse,
) -> AsyncGenerator[str, None]:
    """Generate CSV text stream with Threat Trends, Attack Types, Risk Distribution, and Sender Domains."""
    output = io.StringIO()
    writer = csv.writer(output)

    # 1. Threat Trends Section
    writer.writerow(["# SECTION: THREAT TRENDS"])
    writer.writerow(
        [
            "Timestamp",
            "Total Analyses",
            "Clean",
            "Suspicious",
            "Malicious",
            "Quarantine",
            "Block",
        ]
    )
    for tt in overview.threat_trends:
        writer.writerow(
            [
                tt.timestamp.isoformat(),
                tt.total,
                tt.clean,
                tt.suspicious,
                tt.malicious,
                tt.quarantine,
                tt.block,
            ]
        )
    output.seek(0)
    yield output.read()
    output.truncate(0)
    output.seek(0)

    # 2. Attack Types Section
    writer.writerow([])
    writer.writerow(["# SECTION: ATTACK TYPES"])
    writer.writerow(["Attack Type", "Count", "Percentage"])
    for at in overview.attack_type_trends:
        writer.writerow([at.attack_type, at.count, f"{at.percentage}%"])
    output.seek(0)
    yield output.read()
    output.truncate(0)
    output.seek(0)

    # 3. Risk Distribution Section
    writer.writerow([])
    writer.writerow(["# SECTION: RISK DISTRIBUTION"])
    writer.writerow(["Tier", "Count", "Percentage"])
    for rd in overview.risk_distribution:
        writer.writerow([rd.tier, rd.count, f"{rd.percentage}%"])
    output.seek(0)
    yield output.read()
    output.truncate(0)
    output.seek(0)

    # 4. Sender Domains Section
    writer.writerow([])
    writer.writerow(["# SECTION: SENDER DOMAINS"])
    writer.writerow(
        [
            "Domain",
            "Total Emails",
            "Threat Count",
            "Clean Count",
            "Threat Rate",
        ]
    )
    for sd in overview.sender_domains:
        writer.writerow(
            [
                sd.domain,
                sd.total_emails,
                sd.threat_count,
                sd.clean_count,
                f"{sd.threat_rate}%",
            ]
        )
    output.seek(0)
    yield output.read()
    output.truncate(0)
    output.seek(0)


@router.get(
    "/overview",
    response_model=AnalyticsOverviewResponse,
    summary="Get authoritative security analytics overview directly aggregated from PostgreSQL",
)
async def get_analytics_overview(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
    preset: str | None = Query(
        default=None,
        description="Time window preset ('24h', '7d', '30d', '90d'). Default is '7d'",
    ),
    start: datetime | None = Query(
        default=None,
        description="Custom start timestamp (ISO-8601 string)",
    ),
    end: datetime | None = Query(
        default=None,
        description="Custom end timestamp (ISO-8601 string)",
    ),
) -> AnalyticsOverviewResponse:
    """Return complete analytical summary for threat intelligence, ML performance, and pipeline metrics."""
    _validate_date_params(preset, start, end)

    org_id: uuid.UUID | None = claims.org_id if claims else None
    cache_key = analytics_cache.make_key(
        str(org_id),
        preset,
        start.isoformat() if start else None,
        end.isoformat() if end else None,
    )

    cached = await analytics_cache.get(cache_key)
    if cached is not None:
        return cached

    async with uow:
        result = await uow.analytics.get_overview(
            org_id=org_id,
            start=start,
            end=end,
            preset=preset,
        )
        await analytics_cache.set(cache_key, result, ttl_seconds=30)
        return result


@router.get(
    "/export",
    summary="Export threat analytics data as a streaming CSV file",
)
async def export_analytics_csv(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
    preset: str | None = Query(
        default=None,
        description="Time window preset ('24h', '7d', '30d', '90d'). Default is '7d'",
    ),
    start: datetime | None = Query(
        default=None,
        description="Custom start timestamp (ISO-8601 string)",
    ),
    end: datetime | None = Query(
        default=None,
        description="Custom end timestamp (ISO-8601 string)",
    ),
) -> StreamingResponse:
    """Stream a CSV report containing Threat Trends, Attack Types, Risk Distribution, and Sender Domains."""
    _validate_date_params(preset, start, end)

    async with uow:
        org_id: uuid.UUID | None = claims.org_id if claims else None
        overview = await uow.analytics.get_overview(
            org_id=org_id,
            start=start,
            end=end,
            preset=preset,
        )

    now_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    filename = f"analytics_export_{now_str}.csv"

    return StreamingResponse(
        _generate_analytics_csv(overview),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
