"""Developer-only API endpoints — active only when DEMO_MODE=true or in non-production.

Endpoints:
- POST   /api/v1/dev/demo/seed   — Trigger demo data generation
- DELETE /api/v1/dev/demo/reset  — Clear all demo email and analysis records
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/dev", tags=["Developer & Demo Tools"])


class SeedRequest(BaseModel):
    force: bool = Field(default=False, description="Clear existing demo records and re-seed")


class SeedResponse(BaseModel):
    message: str
    seeded: int
    skipped: int
    failed: int
    total: int
    errors: list[dict[str, Any]] = []


class ResetResponse(BaseModel):
    message: str
    deleted_analyses: int
    deleted_emails: int


@router.post(
    "/demo/seed",
    response_model=SeedResponse,
    summary="Seed demo email dataset through real analysis pipeline",
)
async def seed_demo_data(request: SeedRequest = SeedRequest()) -> SeedResponse:
    """Run genuine analysis pipeline for 25 realistic sample emails."""
    from app.scripts.seed_demo_emails import run_seed

    results = await run_seed(force=request.force)
    return SeedResponse(
        message=(
            f"Seeding completed: {results['seeded']} generated, "
            f"{results['skipped']} skipped, {results['failed']} failed"
        ),
        **results,
    )


@router.delete(
    "/demo/reset",
    response_model=ResetResponse,
    summary="Purge all demo analyses and emails",
)
async def reset_demo_data() -> ResetResponse:
    """Delete all analyses and emails for the default demo organization."""
    from sqlalchemy import delete, select

    from app.infrastructure.db.models.analysis import Analysis
    from app.infrastructure.db.models.email import Email
    from app.infrastructure.db.models.organization import Organization
    from app.infrastructure.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        async with session.begin():
            res = await session.execute(
                select(Organization).where(Organization.slug == "default-tenant")
            )
            org = res.scalar_one_or_none()
            if org is None:
                return ResetResponse(message="No demo organization found.", deleted_analyses=0, deleted_emails=0)

            # Count rows
            a_res = await session.execute(select(Analysis).where(Analysis.org_id == org.id))
            analyses_count = len(a_res.scalars().all())

            e_res = await session.execute(select(Email).where(Email.org_id == org.id))
            emails_count = len(e_res.scalars().all())

            # Delete analyses & emails (cascade deletes child rows)
            await session.execute(delete(Analysis).where(Analysis.org_id == org.id))
            await session.execute(delete(Email).where(Email.org_id == org.id))

    return ResetResponse(
        message=f"Purged {analyses_count} analyses and {emails_count} emails.",
        deleted_analyses=analyses_count,
        deleted_emails=emails_count,
    )
