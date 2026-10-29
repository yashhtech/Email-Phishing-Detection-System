"""Asynchronous email analysis API router.

Endpoints:
- POST /analysis                 — Ingest email, enqueue background analysis job, return analysis_id immediately (<20ms)
- GET  /analysis/{analysis_id}   — Fetch analysis lifecycle state, composite risk score, and forensics
- GET  /analysis/{analysis_id}/stages — Fetch granular stage progression events
- GET  /analysis/worker/health   — Worker pool health and operational telemetry
- WebSocket /ws/analysis/{analysis_id} — Real-time push updates for pipeline stage transitions
"""

from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

import structlog
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.dependencies import get_optional_user_claims, get_uow
from app.api.schemas.history import AnalysisHistoryItem, AnalysisHistoryResponse
from app.infrastructure.db.models.analysis import Analysis
from app.infrastructure.db.models.email import Email
from app.infrastructure.db.models.enums import (
    AnalysisStatus,
    AnalysisVerdict,
    AttackType,
    EmailPriority,
    EmailStatus,
    RiskLevel,
)
from app.infrastructure.db.models.organization import Organization
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.infrastructure.websocket.manager import ws_manager
from app.services.processing.schemas import (
    AnalysisJob,
    AnalysisSubmitResult,
    JobStatus,
    WorkerHealthStatus,
)
from app.services.processing.worker import get_worker_pool, submit_analysis_job
from app.services.token_service import TokenClaims

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["Asynchronous Email Analysis"])


class SubmitAnalysisRequest(BaseModel):
    """Payload for submitting an email for asynchronous analysis."""

    raw_content: str | None = Field(
        default=None,
        description="Raw RFC 822 / .eml MIME text",
        examples=[
            "From: sender@example.com\nTo: recipient@example.com\nSubject: Urgent\n\nPlease review."
        ],
    )
    from_address: str | None = Field(
        default=None,
        description="Sender email address if structured input",
    )
    to_addresses: list[str] = Field(
        default_factory=list,
        description="Recipient email addresses",
    )
    subject: str | None = Field(
        default=None,
        description="Email subject line",
    )
    body_plain: str | None = Field(
        default=None,
        description="Plain text email body",
    )
    body_html: str | None = Field(
        default=None,
        description="Raw HTML body",
    )


async def _resolve_tenant(
    claims: TokenClaims | None,
    uow: UnitOfWork,
) -> tuple[uuid.UUID, uuid.UUID | None]:
    """Resolve organization tenant and user ID from JWT claims or fallback to default."""
    if claims is not None:
        return claims.org_id, claims.user_id

    org_res = await uow.session.execute(  # type: ignore[union-attr]
        select(Organization).where(Organization.slug == "default-tenant")
    )
    demo_org = org_res.scalar_one_or_none()
    if demo_org is None:
        demo_org = Organization(
            name="Security Operations Demo",
            slug="default-tenant",
            primary_domain="demo.security.local",
            is_active=True,
        )
        uow.session.add(demo_org)  # type: ignore[union-attr]
        await uow.session.flush()  # type: ignore[union-attr]
    return demo_org.id, None


@router.post(
    "/analysis",
    response_model=AnalysisSubmitResult,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit email for asynchronous security analysis",
    description=(
        "Enqueues email for full pipeline processing (security analyzers → ML → "
        "Threat Intel → Groq LLM → Risk Engine). Returns immediately with tracking metadata "
        "and WebSocket stream URL."
    ),
)
async def submit_analysis(
    payload: SubmitAnalysisRequest,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)],
) -> AnalysisSubmitResult:
    """Intake email, persist initial records, and enqueue background analysis."""
    # Ensure at least raw_content or from_address/subject/body exists
    raw_content = payload.raw_content
    if not raw_content:
        # Synthesize raw RFC 822 message from structured components
        from_hdr = payload.from_address or "unknown@unknown.local"
        to_hdr = (
            ", ".join(payload.to_addresses) if payload.to_addresses else "undisclosed-recipients:;"
        )
        subj_hdr = payload.subject or "(No Subject)"
        body = payload.body_plain or ""
        raw_content = f"From: {from_hdr}\nTo: {to_hdr}\nSubject: {subj_hdr}\nMIME-Version: 1.0\nContent-Type: text/plain\n\n{body}"

    async with uow:
        org_id, user_id = await _resolve_tenant(claims, uow)

        # 1. Create Email record
        email_record = Email(
            org_id=org_id,
            submitted_by_user_id=user_id,
            message_id=f"<{uuid.uuid4()}@submitted.local>",
            subject=payload.subject or "(Subject pending parse)",
            from_address=payload.from_address or "pending@parse.local",
            from_domain=payload.from_address.split("@")[-1]
            if payload.from_address and "@" in payload.from_address
            else "parse.local",
            to_addresses=payload.to_addresses,
            cc_addresses=[],
            reply_to=None,
            received_at=datetime.now(UTC),
            body_plain=payload.body_plain,
            body_html=payload.body_html,
            source="async_api",
            priority=EmailPriority.NORMAL,
            status=EmailStatus.QUEUED,
        )
        uow.session.add(email_record)  # type: ignore[union-attr]
        await uow.session.flush()  # type: ignore[union-attr]

        # 2. Create Analysis record in QUEUED state
        analysis_record = Analysis(
            email_id=email_record.id,
            org_id=org_id,
            status=AnalysisStatus.QUEUED,
        )
        uow.session.add(analysis_record)  # type: ignore[union-attr]
        await uow.session.flush()  # type: ignore[union-attr]

        analysis_id = analysis_record.id
        email_id = email_record.id
        created_at = analysis_record.created_at or datetime.now(UTC)

        # Commit DB transaction so worker can immediately read records
        await uow.commit()

    # 3. Build immutable AnalysisJob and enqueue
    job = AnalysisJob(
        job_id=str(uuid.uuid4()),
        analysis_id=analysis_id,
        email_id=email_id,
        org_id=org_id,
        raw_content=raw_content,
    )

    await submit_analysis_job(job)

    return AnalysisSubmitResult(
        analysis_id=analysis_id,
        email_id=email_id,
        status=JobStatus.QUEUED,
        created_at=created_at,
        tracking_url=f"/api/v1/analysis/{analysis_id}",
        websocket_url=f"/ws/analysis/{analysis_id}",
    )


@router.get(
    "/analysis/worker/health",
    response_model=WorkerHealthStatus,
    summary="Worker pool health and telemetry",
)
async def get_worker_health() -> WorkerHealthStatus:
    """Return health metrics and operational capacity for background analysis workers."""
    pool = get_worker_pool()
    return pool.get_health()


@router.get(
    "/analysis/history",
    response_model=AnalysisHistoryResponse,
    summary="Paginated analysis history with server-side filtering, searching, and sorting",
)
async def get_analysis_history(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    sort_by: str = Query(
        default="created_at",
        description="Sort field (created_at, risk_score, sender, severity, etc.)",
    ),
    sort_order: str = Query(default="desc", description="Sort direction ('asc' or 'desc')"),
    search: str | None = Query(
        default=None, description="Free-text search across sender, subject, domain"
    ),
    start_date: datetime | None = Query(
        default=None, description="ISO timestamp lower bound filter"
    ),
    end_date: datetime | None = Query(default=None, description="ISO timestamp upper bound filter"),
    severity: str | None = Query(default=None, description="Categorical risk severity filter"),
    attack_type: str | None = Query(default=None, description="Attack vector filter"),
    sender: str | None = Query(default=None, description="Sender email or domain filter"),
    min_risk: int | None = Query(
        default=None, ge=0, le=100, description="Minimum numeric risk score"
    ),
    max_risk: int | None = Query(
        default=None, ge=0, le=100, description="Maximum numeric risk score"
    ),
    status: str | None = Query(
        default=None, description="Processing status filter (queued, processing, completed, failed)"
    ),
    classification: str | None = Query(
        default=None, description="Security verdict classification filter"
    ),
) -> AnalysisHistoryResponse:
    """Retrieve high-density tabular analysis history with server-side filtering and pagination."""
    async with uow:
        org_id, _ = await _resolve_tenant(claims, uow)

        risk_level_enum: RiskLevel | None = None
        if severity and severity.lower() != "all":
            try:
                risk_level_enum = RiskLevel(severity.lower())
            except ValueError:
                pass

        attack_type_enum: AttackType | None = None
        if attack_type and attack_type.lower() != "all":
            try:
                attack_type_enum = AttackType(attack_type.lower())
            except ValueError:
                pass

        status_enum: AnalysisStatus | None = None
        if status and status.lower() != "all":
            status_map = {
                "queued": AnalysisStatus.QUEUED,
                "processing": AnalysisStatus.ANALYZING,
                "completed": AnalysisStatus.COMPLETE,
                "failed": AnalysisStatus.FAILED,
            }
            status_enum = status_map.get(status.lower())

        verdict_enum: AnalysisVerdict | None = None
        if classification and classification.lower() != "all":
            try:
                verdict_enum = AnalysisVerdict(classification.lower())
            except ValueError:
                pass

        raw_items, total_count = await uow.analyses.get_paginated_history(
            org_id=org_id,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
            search=search,
            start_date=start_date,
            end_date=end_date,
            severity=risk_level_enum,
            attack_type=attack_type_enum,
            sender=sender,
            min_risk_score=min_risk,
            max_risk_score=max_risk,
            status=status_enum,
            classification=verdict_enum,
        )

        total_pages = max(1, math.ceil(total_count / page_size))
        items = [AnalysisHistoryItem(**it) for it in raw_items]

        return AnalysisHistoryResponse(
            items=items,
            total_count=total_count,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1,
        )


@router.get(
    "/analysis/{analysis_id}",
    summary="Get analysis status and full forensic results",
)
async def get_analysis_status(
    analysis_id: uuid.UUID,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
) -> dict[str, Any]:
    """Retrieve the current processing state and final results for an analysis job."""
    async with uow:
        analysis = await uow.analyses.get_with_full_details(analysis_id)
        if analysis is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis '{analysis_id}' was not found.",
            )

        # IDOR prevention: ensure analysis belongs to the caller's organisation
        if claims is not None and analysis.org_id != claims.org_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis '{analysis_id}' was not found.",
            )

        status_mapping = {
            AnalysisStatus.QUEUED: "queued",
            AnalysisStatus.ANALYZING: "processing",
            AnalysisStatus.COMPLETE: "completed",

            AnalysisStatus.FAILED: "failed",
            AnalysisStatus.SKIPPED: "failed",
        }

        # Build comprehensive forensic payload
        return {
            "analysis_id": str(analysis.id),
            "email_id": str(analysis.email_id),
            "status": status_mapping.get(analysis.status, "unknown"),
            "raw_status": analysis.status.value,
            "verdict": analysis.verdict.value if analysis.verdict else "unknown",
            "overall_risk_score": analysis.overall_risk_score or 0,
            "risk_level": analysis.risk_level.value if analysis.risk_level else "unknown",
            "started_at": analysis.started_at.isoformat() if analysis.started_at else None,
            "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None,
            "duration_ms": analysis.duration_ms,
            "error_message": analysis.error_message,
            "threat_signals": [
                {
                    "id": str(sig.id),
                    "signal_type": sig.signal_type,
                    "category": sig.category.value,
                    "severity": sig.severity.value,
                    "attack_type": sig.attack_type.value,
                    "confidence": sig.confidence,
                    "source": sig.source_engine,
                    "title": sig.title,
                    "description": sig.description,
                    "indicator_value": sig.indicator_value,
                }
                for sig in (analysis.threat_signals or [])
            ],
            "risk_score": {
                "composite_score": analysis.risk_score.composite_score,
                "risk_level": analysis.risk_score.risk_level.value,
                "spf_subscore": analysis.risk_score.spf_subscore,
                "ml_subscore": analysis.risk_score.ml_subscore,
                "sender_reputation_subscore": analysis.risk_score.sender_reputation_subscore,
                "factor_breakdown": analysis.risk_score.factor_breakdown,
                "scoring_version": analysis.risk_score.scoring_version,
            }
            if analysis.risk_score
            else None,
            "ml_prediction": {
                "model_name": analysis.ml_prediction.model_name,
                "model_version": analysis.ml_prediction.model_version,
                "classification": analysis.ml_prediction.prediction_label,
                "phishing_probability": analysis.ml_prediction.phishing_probability,
                "spam_probability": analysis.ml_prediction.spam_probability,
                "malware_probability": analysis.ml_prediction.malware_probability,
                "confidence": analysis.ml_prediction.confidence_score,
            }
            if analysis.ml_prediction
            else None,
            "llm_analysis": {
                "model_name": analysis.llm_analysis.model_name,
                "prompt_version": analysis.llm_analysis.prompt_version,
                "threat_narrative": analysis.llm_analysis.threat_narrative,
                "executive_summary": analysis.llm_analysis.executive_summary,
                "recommended_action": analysis.llm_analysis.recommended_action,
                "reasoning": analysis.llm_analysis.reasoning,
                "extracted_iocs": analysis.llm_analysis.extracted_iocs,
                "safety_passed": analysis.llm_analysis.safety_passed,
                "confidence_score": analysis.llm_analysis.confidence_score,
                "latency_ms": analysis.llm_analysis.latency_ms,
            }
            if analysis.llm_analysis
            else None,
            "threat_intel_results": [
                {
                    "indicator_type": ti.indicator_type,
                    "indicator_value": ti.indicator_value,
                    "provider": ti.provider,
                    "reputation": ti.reputation_verdict.value,
                    "threat_score": ti.threat_score,
                    "tags": ti.tags,
                    "last_checked_at": ti.last_checked_at.isoformat(),
                }
                for ti in (analysis.threat_intel_results or [])
            ],
        }


@router.get(
    "/analysis/{analysis_id}/stages",
    summary="Get granular stage progress history for an analysis",
)
async def get_analysis_stages(
    analysis_id: uuid.UUID,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
) -> list[dict[str, Any]]:
    """Retrieve chronological log of pipeline stage events for this analysis."""
    async with uow:
        analysis = await uow.analyses.get_by_id(analysis_id)
        if analysis is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis '{analysis_id}' was not found.",
            )

        # IDOR prevention: ensure stages belong to caller's org
        if claims is not None and analysis.org_id != claims.org_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis '{analysis_id}' was not found.",
            )

        events = await uow.analyses.get_events(analysis_id)

        return [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "stage": e.stage,
                "message": e.message,
                "details": e.payload,
                "timestamp": e.created_at.isoformat(),
            }
            for e in sorted(events, key=lambda x: x.created_at)
        ]


# ---------------------------------------------------------------------------
# WebSocket Endpoint for real-time progress events
# ---------------------------------------------------------------------------


@router.websocket("/ws/analysis/{analysis_id}")
async def websocket_analysis_endpoint(
    websocket: WebSocket,
    analysis_id: str,
    token: str | None = Query(default=None, description="JWT access token for authentication"),
) -> None:
    """Stream real-time stage progress and completion events for an analysis job.

    Authentication: pass `?token=<access_token>` in the WebSocket URL query string.
    Browsers cannot send Authorization headers in WebSocket upgrade requests.
    In demo/development mode (no token), the default tenant is used.
    """
    from app.infrastructure.config.settings import get_settings
    from app.infrastructure.db.session import AsyncSessionLocal
    from app.services.token_service import TokenService

    caller_org_id: uuid.UUID | None = None
    if token:
        try:
            token_svc = TokenService(get_settings())
            claims = token_svc.decode_token(token, expected_type="access")
            if claims.is_expired():
                await websocket.close(code=4001, reason="Authentication token expired")
                return
            caller_org_id = claims.org_id
        except Exception:
            await websocket.close(code=4001, reason="Invalid or expired authentication token")
            return

    # If an authenticated user connects, enforce tenant isolation
    if caller_org_id is not None:
        try:
            analysis_uuid = uuid.UUID(analysis_id)
        except ValueError:
            await websocket.close(code=4002, reason="Invalid analysis ID format")
            return

        async with AsyncSessionLocal() as session:
            from sqlalchemy import select as sa_select

            result = await session.execute(
                sa_select(Analysis.org_id).where(Analysis.id == analysis_uuid)
            )
            row = result.scalar_one_or_none()
            if row is None or row != caller_org_id:
                await websocket.close(code=4003, reason="Analysis not found or access denied")
                return

    await ws_manager.connect(websocket, analysis_id)
    try:
        # Send initial confirmation event
        await ws_manager.send_personal_message(
            {
                "analysis_id": analysis_id,
                "event": "connected",
                "message": f"Subscribed to live updates for analysis {analysis_id}",
            },
            websocket,
        )

        # Keep connection open, respond to ping/heartbeat from client
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket, analysis_id)
    except Exception as exc:
        logger.debug("ws_connection_closed", analysis_id=analysis_id, error=str(exc))
        await ws_manager.disconnect(websocket, analysis_id)

