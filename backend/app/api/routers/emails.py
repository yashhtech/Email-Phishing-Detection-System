"""Email intake, parsing, and forensic threat analysis API router.

Endpoints:
- POST /emails/analyze         — Analyze structured email fields
- POST /emails/analyze/raw     — Analyze raw RFC 822 / .eml text
- POST /emails/analyze/upload  — Upload .eml file and optional attachments
- GET  /emails/{id}            — Get complete email forensic details
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, File, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.dependencies import get_optional_user_claims, get_uow
from app.infrastructure.websocket.manager import ws_manager
from app.api.schemas.email import (
    EmailAnalysisSubmitResponse,
    ExtractedAttachmentResponse,
    ExtractedHeadersResponse,
    ExtractedURLResponse,
    RawEmailSubmitRequest,
    StructuredEmailSubmitRequest,
)
from app.domain.exceptions.domain_exceptions import NotFoundError, ValidationError
from app.infrastructure.db.models.analysis import Analysis, RiskScore, ThreatSignal
from app.infrastructure.db.models.email import Attachment, Email, EmailHeader, EmailURL
from app.infrastructure.db.models.enums import (
    AnalysisStatus,
    AnalysisVerdict,
    AttackType,
    AuthResultStatus,
    EmailPriority,
    EmailStatus,
    RiskLevel,
    ThreatCategory,
    ThreatSeverity,
)
from app.infrastructure.db.models.organization import Organization
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.services.email_parser_service import (
    EmailParserService,
    ParsedEmailArtifacts,
)
from app.services.token_service import TokenClaims

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/emails", tags=["Email Analyzer"])

# Maximum upload limits (25 MB for .eml, 10 MB per attachment)
_MAX_EML_BYTES = 25 * 1024 * 1024
_MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
_ALLOWED_EML_TYPES = frozenset({
    "message/rfc822",
    "application/octet-stream",
    "text/plain",
    "application/eml",
})


async def _resolve_tenant(
    claims: TokenClaims | None,
    uow: UnitOfWork,
) -> tuple[uuid.UUID, uuid.UUID | None]:
    """Resolve org_id and optional user_id from JWT claims or default demo tenant."""
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


def _calculate_signals(
    artifacts: ParsedEmailArtifacts,
) -> tuple[float, RiskLevel, list[str]]:
    """Compute heuristic preliminary risk score from forensic signals."""
    score = 0.0
    signals: list[str] = []

    if artifacts.headers.spf_status == AuthResultStatus.FAIL:
        score += 25.0
        signals.append(
            "SPF authentication failed: Sender IP is not authorized by domain SPF policy"
        )
    elif artifacts.headers.spf_status == AuthResultStatus.SOFTFAIL:
        score += 15.0
        signals.append("SPF authentication softfailed")

    if artifacts.headers.dkim_status == AuthResultStatus.FAIL:
        score += 25.0
        signals.append("DKIM verification failed: Cryptographic message signature is invalid")

    if artifacts.headers.dmarc_status == AuthResultStatus.FAIL:
        score += 30.0
        signals.append(
            "DMARC alignment failed: From domain does not align with authenticated identities"
        )

    if artifacts.reply_to and "@" in artifacts.reply_to:
        reply_domain = artifacts.reply_to.split("@")[-1].lower()
        if reply_domain != artifacts.from_domain:
            score += 20.0
            signals.append(
                f"Reply-To domain mismatch: Reply-To ({reply_domain}) differs from From ({artifacts.from_domain})"
            )

    for u in artifacts.urls:
        if u.is_ip_address:
            score += 35.0
            signals.append(f"Direct IP URL detected: {u.defanged_url} uses bare numeric IP address")
        if u.is_suspicious_tld:
            score += 20.0
            signals.append(f"Suspicious high-risk TLD detected: {u.domain}")

    for att in artifacts.attachments:
        if att.is_executable:
            score += 45.0
            signals.append(f"Dangerous executable attachment detected: {att.filename}")
        if att.is_archive:
            score += 15.0
            signals.append(f"Archive file attached: {att.filename}")

    score = min(100.0, score)
    if score >= 75.0:
        level = RiskLevel.CRITICAL
    elif score >= 50.0:
        level = RiskLevel.HIGH
    elif score >= 25.0:
        level = RiskLevel.MEDIUM
    elif score > 0.0:
        level = RiskLevel.LOW
    else:
        level = RiskLevel.SAFE
    return score, level, signals


def _build_response(
    email_record: Email,
    analysis_record: Analysis,
    risk: RiskScore | None,
    artifacts: ParsedEmailArtifacts,
    risk_score_val: float,
    risk_level: RiskLevel,
    threat_signals: list[str],
) -> EmailAnalysisSubmitResponse:
    lvl_val = risk_level.value.lower()
    score_int = int(risk_score_val)

    # Explanation based on severity / score
    if lvl_val in ("critical", "high") or score_int >= 70:
        explanation = (
            "Critical threat indicators detected including suspected credential harvesting, "
            "severe authentication failures, or deceptive lookalike domains."
        )
    elif lvl_val == "medium" or score_int >= 30:
        explanation = (
            "Unusual patterns detected such as unverified sender authentication, "
            "suspicious wording, or unverified external links."
        )
    else:
        explanation = (
            "All core security authentication checks passed. "
            "No deceptive links, malware indicators, or sender impersonation detected."
        )

    # Top findings
    findings = [s.split(":", 1)[0].strip() if ":" in s else s.strip() for s in threat_signals[:3]]
    if not findings:
        findings = [
            "Sender authentication passed (SPF/DKIM/DMARC)",
            "No suspicious or defanged URLs detected",
            "No weaponized or executable attachments found",
        ]

    # Security checks summary
    security_checks = {
        "spf": artifacts.headers.spf_status.value if artifacts.headers.spf_status else "unknown",
        "dkim": artifacts.headers.dkim_status.value if artifacts.headers.dkim_status else "unknown",
        "dmarc": artifacts.headers.dmarc_status.value if artifacts.headers.dmarc_status else "unknown",
        "urls_analyzed": len(artifacts.urls),
        "attachments_analyzed": len(artifacts.attachments),
    }

    # Threat categories supported by analysis
    threat_categories: list[str] = []
    if any("SPF" in s or "DKIM" in s or "DMARC" in s or "Reply-To" in s for s in threat_signals):
        threat_categories.append("spoofing")
    if any("URL" in s or "link" in s.lower() or "ip address" in s.lower() for s in threat_signals):
        threat_categories.append("phishing")
    if any(a.is_executable for a in artifacts.attachments):
        threat_categories.append("malware")
    if not threat_categories and (lvl_val in ("critical", "high")):
        threat_categories.append("phishing")

    # Recommendations matching prompt requirements
    if lvl_val in ("critical", "high") or score_int >= 70:
        recommendations = [
            "Do not click links, open attachments, reply, or share credentials or financial information. Report this email to your security team."
        ]
    elif lvl_val == "medium" or score_int >= 30:
        recommendations = [
            "Do not click links or open attachments until you independently verify the sender."
        ]
    else:
        recommendations = [
            "No major threat indicators were detected. Still verify unexpected requests before sharing sensitive information."
        ]

    return EmailAnalysisSubmitResponse(
        email_id=str(email_record.id),
        analysis_id=str(analysis_record.id),
        status=email_record.status.value,
        verdict=analysis_record.verdict.value if analysis_record.verdict else "unknown",
        severity=lvl_val,
        risk_score=risk_score_val,
        message_id=artifacts.message_id,
        from_address=artifacts.from_address,
        from_domain=artifacts.from_domain,
        to_addresses=artifacts.to_addresses,
        cc_addresses=artifacts.cc_addresses,
        reply_to=artifacts.reply_to,
        subject=artifacts.subject,
        received_at=artifacts.received_at,
        body_preview=artifacts.body_preview,
        body_plain=artifacts.body_plain,
        body_html=artifacts.body_html,
        headers=ExtractedHeadersResponse(
            message_id=artifacts.headers.message_id,
            from_raw=artifacts.headers.from_raw,
            to_raw=artifacts.headers.to_raw,
            cc_raw=artifacts.headers.cc_raw,
            reply_to=artifacts.headers.reply_to,
            subject=artifacts.headers.subject,
            date=artifacts.headers.date,
            spf_status=artifacts.headers.spf_status.value,
            spf_details=artifacts.headers.spf_details,
            dkim_status=artifacts.headers.dkim_status.value,
            dkim_details=artifacts.headers.dkim_details,
            dmarc_status=artifacts.headers.dmarc_status.value,
            dmarc_details=artifacts.headers.dmarc_details,
            hop_count=artifacts.headers.hop_count,
            raw_headers=artifacts.headers.raw_headers,
        ),
        urls=[
            ExtractedURLResponse(
                url=u.url,
                domain=u.domain,
                scheme=u.scheme,
                path=u.path,
                is_ip_address=u.is_ip_address,
                defanged_url=u.defanged_url,
                reputation=u.reputation.value,
                is_suspicious_tld=u.is_suspicious_tld,
            )
            for u in artifacts.urls
        ],
        attachments=[
            ExtractedAttachmentResponse(
                filename=a.filename,
                content_type=a.content_type,
                size_bytes=a.size_bytes,
                sha256=a.sha256,
                is_executable=a.is_executable,
                is_archive=a.is_archive,
            )
            for a in artifacts.attachments
        ],
        initial_risk_score=risk_score_val,
        initial_risk_level=risk_level.value,
        threat_signals=threat_signals,
        explanation=explanation,
        findings=findings,
        security_checks=security_checks,
        threat_categories=threat_categories,
        recommendations=recommendations,
        completed_at=analysis_record.completed_at or datetime.now(UTC),
    )


async def _persist_and_respond(
    artifacts: ParsedEmailArtifacts,
    claims: TokenClaims | None,
    uow: UnitOfWork,
) -> EmailAnalysisSubmitResponse:
    """Persist email, headers, URLs, attachments, analysis, risk, and signals atomically."""
    risk_score_val, risk_level, threat_signals = _calculate_signals(artifacts)

    async with uow:
        org_id, user_id = await _resolve_tenant(claims, uow)
        # 1. Email record
        email_record = Email(
            org_id=org_id,
            submitted_by_user_id=user_id,
            message_id=artifacts.message_id,
            subject=artifacts.subject,
            from_address=artifacts.from_address,
            from_domain=artifacts.from_domain,
            to_addresses=artifacts.to_addresses,
            cc_addresses=artifacts.cc_addresses,
            reply_to=artifacts.reply_to,
            received_at=artifacts.received_at,
            body_plain=artifacts.body_plain,
            body_html=artifacts.body_html,
            body_preview=artifacts.body_preview,
            source="manual_analyzer",
            priority=EmailPriority.HIGH if risk_score_val >= 50.0 else EmailPriority.NORMAL,
            status=EmailStatus.COMPLETE,
            has_attachments=len(artifacts.attachments) > 0,
            attachment_count=len(artifacts.attachments),
        )
        uow.session.add(email_record)  # type: ignore[union-attr]
        await uow.session.flush()  # type: ignore[union-attr]

        # 2. EmailHeader record — using actual model column names
        header_record = EmailHeader(
            email_id=email_record.id,
            spf_verdict=artifacts.headers.spf_status,
            spf_record=artifacts.headers.spf_details,
            dkim_verdict=artifacts.headers.dkim_status,
            dmarc_verdict=artifacts.headers.dmarc_status,
            authentication_results_raw=str(
                artifacts.headers.raw_headers.get("Authentication-Results", "")
            ),
            routing_hops=artifacts.headers.route_hops,
            raw_headers=artifacts.headers.raw_headers,
        )
        uow.session.add(header_record)  # type: ignore[union-attr]

        # 3. EmailURL records — using actual model column names
        for u in artifacts.urls:
            url_rec = EmailURL(
                email_id=email_record.id,
                raw_url=u.url,
                domain=u.domain,
                reputation=u.reputation,
            )
            uow.session.add(url_rec)  # type: ignore[union-attr]

        # 4. Attachment records — using actual model column names
        for att in artifacts.attachments:
            import hashlib

            md5_hex = hashlib.md5(att.raw_data or b"").hexdigest()
            ext = att.filename.rsplit(".", 1)[-1].lower() if "." in att.filename else ""
            att_rec = Attachment(
                email_id=email_record.id,
                filename=att.filename,
                extension=ext,
                mime_type=att.content_type,
                file_size_bytes=att.size_bytes,
                md5_hash=md5_hex,
                sha256_hash=att.sha256,
                is_executable=att.is_executable,
            )
            uow.session.add(att_rec)  # type: ignore[union-attr]

        # 5. Analysis record
        verdict: AnalysisVerdict = (
            AnalysisVerdict.MALICIOUS
            if risk_score_val >= 75.0
            else AnalysisVerdict.SUSPICIOUS
            if risk_score_val >= 50.0
            else AnalysisVerdict.CLEAN
        )
        analysis_record = Analysis(
            email_id=email_record.id,
            org_id=org_id,
            status=AnalysisStatus.COMPLETE,
            verdict=verdict,
            overall_risk_score=int(risk_score_val),
            risk_level=risk_level,
            model_versions={"pipeline": "1.0.0"},
        )
        uow.session.add(analysis_record)  # type: ignore[union-attr]
        await uow.session.flush()  # type: ignore[union-attr]

        # 6. RiskScore record — using actual model column names
        risk_record = RiskScore(
            analysis_id=analysis_record.id,
            org_id=org_id,
            composite_score=int(risk_score_val),
            risk_level=risk_level,
            spf_subscore=30.0 if artifacts.headers.spf_status == AuthResultStatus.FAIL else 0.0,
            url_subscore=35.0 if any(u.is_ip_address for u in artifacts.urls) else 0.0,
            attachment_subscore=45.0
            if any(a.is_executable for a in artifacts.attachments)
            else 0.0,
        )
        uow.session.add(risk_record)  # type: ignore[union-attr]

        # 7. ThreatSignal records — using actual model column names
        for sig in threat_signals:
            sig_rec = ThreatSignal(
                analysis_id=analysis_record.id,
                org_id=org_id,
                signal_type="heuristic",
                title=sig.split(":", 1)[0][:255],
                description=sig,
                category=ThreatCategory.PHISHING,
                severity=ThreatSeverity.HIGH if risk_score_val >= 50 else ThreatSeverity.MEDIUM,
                attack_type=AttackType.SPEAR_PHISHING if "Reply-To" in sig else AttackType.UNKNOWN,
                confidence=0.85,
                source_engine="header",
            )
            uow.session.add(sig_rec)  # type: ignore[union-attr]

        # Snap IDs before session closes
        email_id_snapped = email_record.id
        analysis_id_snapped = analysis_record.id
        verdict_val = analysis_record.verdict

    # Ensure IDs are final UUIDs
    email_record.id = email_id_snapped
    analysis_record.id = analysis_id_snapped
    analysis_record.verdict = verdict_val

    resp = _build_response(
        email_record,
        analysis_record,
        risk_record,
        artifacts,
        risk_score_val,
        risk_level,
        threat_signals,
    )

    # Broadcast completed event to all WebSocket listeners (dashboard & analyzer)
    try:
        await ws_manager.broadcast_event(
            analysis_id=str(analysis_record.id),
            status="completed",
            stage="completed",
            data={
                "analysis_id": str(analysis_record.id),
                "verdict": resp.verdict,
                "severity": resp.severity,
                "risk_score": int(risk_score_val),
                "subject": resp.subject,
                "sender": resp.from_address,
                "explanation": resp.explanation,
                "findings": resp.findings,
                "security_checks": resp.security_checks,
                "threat_categories": resp.threat_categories,
                "recommendations": resp.recommendations,
                "completed_at": resp.completed_at.isoformat() if resp.completed_at else datetime.now(UTC).isoformat(),
            },
        )
    except Exception as exc:
        logger.debug("ws_broadcast_failed", error=str(exc))

    return resp


# ---------------------------------------------------------------------------
# POST /emails/analyze (Structured form fields)
# ---------------------------------------------------------------------------


@router.post(
    "/analyze",
    response_model=EmailAnalysisSubmitResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit structured email for threat analysis",
)
async def analyze_structured_email(
    body: StructuredEmailSubmitRequest,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
) -> EmailAnalysisSubmitResponse:
    artifacts = EmailParserService.parse_structured(
        from_address=body.from_address,
        to_addresses=body.to_addresses,
        subject=body.subject,
        body_plain=body.body_plain,
        body_html=body.body_html,
        cc_addresses=body.cc_addresses,
        reply_to=body.reply_to,
        raw_headers_str=body.raw_headers,
    )
    return await _persist_and_respond(artifacts, claims, uow)


# ---------------------------------------------------------------------------
# POST /emails/analyze/raw (Pasted complete email)
# ---------------------------------------------------------------------------


@router.post(
    "/analyze/raw",
    response_model=EmailAnalysisSubmitResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit raw RFC 822 / .eml text for threat analysis",
)
async def analyze_raw_email(
    body: RawEmailSubmitRequest,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
) -> EmailAnalysisSubmitResponse:
    artifacts = EmailParserService.parse_raw_eml(body.raw_content)
    return await _persist_and_respond(artifacts, claims, uow)


# ---------------------------------------------------------------------------
# POST /emails/analyze/upload (.eml file upload)
# ---------------------------------------------------------------------------


@router.post(
    "/analyze/upload",
    response_model=EmailAnalysisSubmitResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload .eml file and optional attachments for threat analysis",
)
async def upload_and_analyze_email(
    eml_file: Annotated[UploadFile, File(description=".eml file to analyze")],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    attachments: list[UploadFile] = File(default=[]),
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
) -> EmailAnalysisSubmitResponse:
    import os

    content = await eml_file.read()
    if not content:
        raise ValidationError("Uploaded .eml file is empty")

    if len(content) > _MAX_EML_BYTES:
        raise ValidationError(
            f"Uploaded .eml file exceeds the 25 MB size limit ({len(content):,} bytes)"
        )

    # Basic MIME type guard — only accept email-like content types
    content_type = (eml_file.content_type or "application/octet-stream").split(";")[0].strip()
    if content_type not in _ALLOWED_EML_TYPES:
        raise ValidationError(
            f"Invalid file type '{content_type}'. Only .eml files are accepted."
        )

    artifacts = EmailParserService.parse_raw_eml(content)

    for att in attachments:
        if att.filename:
            # Sanitize filename: strip path traversal sequences and normalize
            safe_filename = os.path.basename(att.filename.replace("\\", "/"))
            if not safe_filename or safe_filename.startswith("."):
                safe_filename = "attachment"

            att_data = await att.read()
            if not att_data:
                continue

            if len(att_data) > _MAX_ATTACHMENT_BYTES:
                logger.warning(
                    "attachment_size_limit_exceeded",
                    filename=safe_filename,
                    size=len(att_data),
                )
                continue

            extra = EmailParserService._process_attachment(
                safe_filename, att.content_type or "application/octet-stream", att_data
            )
            artifacts.attachments.append(extra)

    return await _persist_and_respond(artifacts, claims, uow)



# ---------------------------------------------------------------------------
# GET /emails/{email_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{email_id}",
    response_model=EmailAnalysisSubmitResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve analyzed email record by ID",
)
async def get_email_analysis(
    email_id: str,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    claims: Annotated[TokenClaims | None, Depends(get_optional_user_claims)] = None,
) -> EmailAnalysisSubmitResponse:
    try:
        eid = uuid.UUID(email_id)
    except ValueError as exc:
        raise ValidationError(f"'{email_id}' is not a valid UUID") from exc

    async with uow:
        caller_org_id, _ = await _resolve_tenant(claims, uow)

        stmt = (
            select(Email)
            .options(
                selectinload(Email.header),
                selectinload(Email.urls),
                selectinload(Email.attachments),
                selectinload(Email.analysis).selectinload(Analysis.risk_score),
                selectinload(Email.analysis).selectinload(Analysis.threat_signals),
            )
            .where(Email.id == eid)
            .where(Email.deleted_at.is_(None))
            .where(Email.org_id == caller_org_id)  # Tenant isolation — IDOR prevention
        )
        res = await uow.session.execute(stmt)  # type: ignore[union-attr]
        email_record = res.scalar_one_or_none()

    if email_record is None:
        raise NotFoundError("Email", email_id)


    header = email_record.header
    analysis = email_record.analysis
    risk = analysis.risk_score if analysis else None

    return EmailAnalysisSubmitResponse(
        email_id=str(email_record.id),
        analysis_id=str(analysis.id) if analysis else str(uuid.uuid4()),
        status=email_record.status.value,
        verdict=analysis.verdict.value if (analysis and analysis.verdict) else "unknown",
        message_id=email_record.message_id,
        from_address=email_record.from_address,
        from_domain=email_record.from_domain,
        to_addresses=email_record.to_addresses,
        cc_addresses=email_record.cc_addresses,
        reply_to=email_record.reply_to,
        subject=email_record.subject,
        received_at=email_record.received_at,
        body_preview=email_record.body_preview,
        body_plain=email_record.body_plain,
        body_html=email_record.body_html,
        headers=ExtractedHeadersResponse(
            message_id=email_record.message_id,
            from_raw=email_record.from_address,
            to_raw=email_record.to_addresses,
            cc_raw=email_record.cc_addresses,
            reply_to=email_record.reply_to,
            subject=email_record.subject,
            date=email_record.received_at,
            spf_status=header.spf_verdict.value if (header and header.spf_verdict) else "none",
            spf_details=header.spf_record if header else None,
            dkim_status=header.dkim_verdict.value if (header and header.dkim_verdict) else "none",
            dkim_details=header.dkim_selector if header else None,
            dmarc_status=header.dmarc_verdict.value
            if (header and header.dmarc_verdict)
            else "none",
            dmarc_details=header.dmarc_policy if header else None,
            hop_count=len(header.routing_hops) if header else 0,
            raw_headers=dict(header.raw_headers) if header else {},
        ),
        urls=[
            ExtractedURLResponse(
                url=u.raw_url,
                domain=u.domain,
                scheme="https",
                path="/",
                is_ip_address=False,
                defanged_url=u.raw_url.replace("http://", "hxxp://").replace(
                    "https://", "hxxps://"
                ),
                reputation=u.reputation.value,
                is_suspicious_tld=False,
            )
            for u in email_record.urls
        ],
        attachments=[
            ExtractedAttachmentResponse(
                filename=a.filename,
                content_type=a.mime_type or "application/octet-stream",
                size_bytes=a.file_size_bytes,
                sha256=a.sha256_hash,
                is_executable=a.is_executable,
                is_archive=False,
            )
            for a in email_record.attachments
        ],
        initial_risk_score=float(risk.composite_score) if risk else 0.0,
        initial_risk_level=risk.risk_level.value if risk else "safe",
        threat_signals=[
            s.description for s in (analysis.threat_signals if analysis else []) if s.description
        ],
    )
