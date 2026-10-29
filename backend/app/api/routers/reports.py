"""Security Incident Reporting API router.

Endpoints:
- GET /api/v1/reports/analysis/{analysis_id} — Generate authoritative analysis report (JSON or HTML)

Security & Compliance:
- Strictly enforces multi-tenant boundary checks (cross-tenant access prohibited).
- Excludes and redacts all provider API keys, bearer tokens, and internal credentials.
- Records every report generation event in immutable audit logs.
"""

from __future__ import annotations

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy import select

from app.api.dependencies import get_optional_user_claims, get_uow
from app.api.schemas.report import AnalysisReportResponse
from app.domain.exceptions.domain_exceptions import ForbiddenError, NotFoundError
from app.infrastructure.db.models.audit import AuditLog
from app.infrastructure.db.models.enums import AuditAction
from app.infrastructure.db.models.organization import Organization
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.services.report_service import ReportService
from app.services.token_service import TokenClaims

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/reports", tags=["Reports"])


async def _resolve_tenant_and_user(
    claims: TokenClaims | None,
    uow: UnitOfWork,
) -> tuple[uuid.UUID, uuid.UUID | None, str | None]:
    """Resolve (org_id, user_id, user_email) from JWT claims or fallback to demo tenant."""
    if claims is not None:
        user = await uow.users.get_by_id(claims.user_id)
        email = user.email if user else None
        return claims.org_id, claims.user_id, email

    # Fallback to default demo organization if unauthenticated in dev/demo mode
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
    return demo_org.id, None, "demo.analyst@security.local"


@router.get(
    "/analysis/{analysis_id}",
    response_model=AnalysisReportResponse,
    responses={
        200: {
            "content": {
                "application/json": {},
                "text/html": {},
            },
            "description": "Comprehensive security analysis report in requested format.",
        },
    },
    summary="Generate comprehensive email threat incident report",
    description=(
        "Compiles forensic metadata, multi-engine security signals, ML classification, "
        "Groq semantic reasoning, and external threat intelligence into an authoritative report. "
        "Supports JSON output or executive-ready printable HTML. All report generations are "
        "audit-logged for compliance."
    ),
)
async def generate_analysis_report(
    analysis_id: uuid.UUID,
    request: Request,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
    format_type: str = Query(
        default="json",
        alias="format",
        description="Report format: 'json' for structured telemetry or 'html' for printable layout.",
        pattern="^(json|html)$",
    ),
    accept: Annotated[str | None, Header()] = None,
) -> Response:
    """Generate and return an authoritative email threat analysis report."""
    # Determine requested format (query parameter takes precedence over Accept header)
    wants_html = format_type.lower() == "html" or (
        format_type.lower() == "json"
        and accept
        and "text/html" in accept
        and "application/json" not in accept
    )

    ip = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent")

    async with uow:
        # Load analysis with all forensic sub-engine outputs
        analysis = await uow.analyses.get_with_full_details(analysis_id)
        if analysis is None:
            raise NotFoundError("Analysis", str(analysis_id))

        caller_org_id, actor_user_id, actor_email = await _resolve_tenant_and_user(claims, uow)

        # Multi-tenant Authorization Check:
        # The caller must belong to the organization that owns this analysis record.
        if analysis.org_id != caller_org_id:
            logger.warning(
                "unauthorized_report_access_attempt",
                analysis_id=str(analysis_id),
                analysis_org_id=str(analysis.org_id),
                caller_org_id=str(caller_org_id),
                actor_user_id=str(actor_user_id) if actor_user_id else None,
            )
            raise ForbiddenError("You do not have authorization to view reports for another organization.")

        # Resolve organization display name
        org_res = await uow.session.execute(  # type: ignore[union-attr]
            select(Organization.name).where(Organization.id == analysis.org_id)
        )
        org_name = org_res.scalar_one_or_none()

        # Build clean, sanitized report
        report = ReportService.build_report(
            analysis,
            actor_email=actor_email,
            actor_user_id=actor_user_id,
            org_name=org_name,
        )

        # Record audit log entry (regulatory & security compliance)
        audit_entry = AuditLog(
            org_id=analysis.org_id,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            actor_ip=ip,
            actor_user_agent=user_agent,
            event_type="ANALYSIS_REPORT_GENERATED",
            resource_type="analysis_report",
            resource_id=str(analysis_id),
            action=AuditAction.EXPORT,
            before_state=None,
            after_state=None,
            metadata_payload={
                "report_id": str(report.report_id),
                "format": "html" if wants_html else "json",
                "engine_version": report.engine_version,
                "scoring_version": report.scoring_version,
                "verdict": report.classification.verdict,
                "risk_score": report.risk_score.overall_risk_score,
                "risk_level": report.risk_score.risk_level,
                "signals_count": len(report.security_signals),
                "evidence_count": len(report.evidence),
                "has_ml": report.ml_analysis is not None,
                "has_groq": report.groq_analysis is not None,
            },
            correlation_id=uuid.uuid4(),
        )
        await uow.audit_logs.create(audit_entry)
        await uow.commit()

        logger.info(
            "analysis_report_generated",
            analysis_id=str(analysis_id),
            report_id=str(report.report_id),
            format="html" if wants_html else "json",
            actor=actor_email,
        )

        if wants_html:
            html_content = ReportService.render_html(report)
            return HTMLResponse(
                content=html_content,
                status_code=status.HTTP_200_OK,
                headers={
                    "Content-Disposition": f'inline; filename="report_{analysis_id}.html"',
                    "X-Report-ID": str(report.report_id),
                },
            )

        # Return structured JSON
        return Response(
            content=report.model_dump_json(),
            media_type="application/json",
            status_code=status.HTTP_200_OK,
            headers={
                "X-Report-ID": str(report.report_id),
            },
        )
