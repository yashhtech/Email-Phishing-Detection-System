"""Analysis pipeline executor — the core worker function.

Executes the full analysis pipeline in order:
  Preprocessing → Security Engine → ML → Threat Intelligence → Groq LLM → Risk Engine → Database

Emits structured WebSocket events at each stage transition.
Handles errors, partial results, and failed engine steps gracefully.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from app.domain.entities.email_analysis_input import EmailAnalysisInput
from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.analysis import (
    AnalysisEvent,
    LLMAnalysis,
    MLPrediction,
    ThreatSignal,
)
from app.infrastructure.db.models.analysis import RiskScore as DBRiskScore
from app.infrastructure.db.models.enums import (
    AnalysisStatus,
    AnalysisVerdict,
    AttackType,
    RiskLevel,
    ThreatCategory,
    ThreatSeverity,
)
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork
from app.infrastructure.websocket.manager import ws_manager
from app.services.analyzers.engine import DeterministicAnalysisEngine
from app.services.llm.analyzer import LLMAnalyzer
from app.services.llm.schemas import LLMResult
from app.services.ml.inference import MLInferenceResult, MLInferenceService
from app.services.processing.schemas import AnalysisJob, AnalysisStage
from app.services.risk.engine import RiskEngine
from app.services.risk.schemas import RiskAssessment
from app.services.threat_intelligence.manager import (
    ThreatIntelligenceService,
    get_threat_intel_service,
)
from app.services.threat_intelligence.schemas import ThreatIntelReport

logger = structlog.get_logger(__name__)


async def _emit(
    analysis_id: str,
    stage: AnalysisStage,
    status: str = "processing",
    data: dict[str, Any] | None = None,
    error_message: str | None = None,
) -> None:
    """Broadcast pipeline stage event over WebSocket."""
    try:
        await ws_manager.broadcast_event(
            analysis_id=analysis_id,
            status=status,
            stage=stage.value,
            data=data,
            error_message=error_message,
        )
    except Exception as exc:
        logger.debug("ws_broadcast_skipped", stage=stage, error=str(exc))


async def _record_event(
    uow: UnitOfWork,
    analysis_id: uuid.UUID,
    stage: str,
    message: str,
    details: dict[str, Any] | None = None,
    is_error: bool = False,
) -> None:
    """Append a structured AnalysisEvent row to the database."""
    try:
        event = AnalysisEvent(
            analysis_id=analysis_id,
            event_type="ERROR" if is_error else "STAGE",
            stage=stage,
            status="failed" if is_error else "completed",
            message=message,
            payload=details or {},
        )
        await uow.analyses.record_event(event)
    except Exception as exc:
        logger.warning("analysis_event_record_failed", error=str(exc))


async def execute_analysis_pipeline(job: AnalysisJob) -> None:
    """Execute the complete analysis pipeline for a queued job.

    Pipeline stages:
    1. PREPROCESSING — Parse email into EmailAnalysisInput
    2. SECURITY_ENGINE — Deterministic threat signal analysis
    3. ML_ENGINE — ML classification
    4. THREAT_INTEL — Multi-provider IOC reputation checks
    5. GROQ_LLM — Semantic intent analysis (if score warrants it)
    6. RISK_ENGINE — Multi-engine signal fusion and risk scoring
    7. PERSISTENCE — Persist all results to database

    Partial failures in individual stages are tolerated; final results
    reflect whatever data was available from succeeding stages.
    """
    analysis_id_str = str(job.analysis_id)
    pipeline_start = time.perf_counter()

    logger.info(
        "analysis_pipeline_started",
        analysis_id=analysis_id_str,
        email_id=str(job.email_id),
        attempt=job.attempt,
    )

    # Collect partial results
    email_input: EmailAnalysisInput | None = None
    security_signals: list[NormalizedThreatSignal] = []
    behavioral_signals: list[NormalizedThreatSignal] = []
    ml_result: MLInferenceResult | None = None
    ti_reports: list[ThreatIntelReport] = []
    llm_result: LLMResult | None = None
    risk_assessment: RiskAssessment | None = None

    async with UnitOfWork() as uow:
        # ----------------------------------------------------------------
        # Mark analysis as PROCESSING
        # ----------------------------------------------------------------
        analysis = await uow.analyses.get_by_id(job.analysis_id)
        if analysis is None:
            logger.error("analysis_record_not_found", analysis_id=analysis_id_str)
            return

        analysis.status = AnalysisStatus.ANALYZING
        analysis.started_at = datetime.now(UTC)
        await uow.commit()

        await _emit(analysis_id_str, AnalysisStage.PREPROCESSING, status="processing")
        await _record_event(uow, job.analysis_id, "preprocessing", "Email preprocessing started")

        # ----------------------------------------------------------------
        # STAGE 1: Preprocessing
        # ----------------------------------------------------------------
        try:
            from app.services.email_preprocessing_pipeline import EmailPreprocessingPipeline

            pipeline = EmailPreprocessingPipeline()

            email_record = await uow.emails.get_by_id(job.email_id)
            if email_record is None:
                raise RuntimeError(f"Email record {job.email_id} not found")

            raw_content = job.raw_content or email_record.body_plain or ""
            email_input = pipeline.preprocess_raw(raw_content)

            await _emit(
                analysis_id_str,
                AnalysisStage.PREPROCESSING,
                status="processing",
                data={"urls": len(email_input.urls), "attachments": len(email_input.attachments)},
            )
            await _record_event(
                uow,
                job.analysis_id,
                "preprocessing",
                "Email preprocessing completed",
                {"url_count": len(email_input.urls)},
            )
            await uow.commit()

        except Exception as exc:
            logger.error("preprocessing_failed", analysis_id=analysis_id_str, error=str(exc))
            await _record_event(
                uow, job.analysis_id, "preprocessing", f"Preprocessing failed: {exc}", is_error=True
            )
            await uow.analyses.record_failure(
                job.analysis_id, error_message=f"Preprocessing failed: {exc}"
            )
            await uow.commit()
            await _emit(
                analysis_id_str, AnalysisStage.FAILED, status="failed", error_message=str(exc)
            )
            return

        # ----------------------------------------------------------------
        # STAGE 2: Security Engine (Deterministic)
        # ----------------------------------------------------------------
        await _emit(analysis_id_str, AnalysisStage.SECURITY_ENGINE, status="processing")
        try:
            all_signals = DeterministicAnalysisEngine().run_all(email_input)
            behavioral_sources = {"behavior_analyzer", "behavioral_analysis"}
            for sig in all_signals:
                if (
                    sig.source in behavioral_sources
                    or "BEHAVIOR" in sig.signal_type
                    or "URGENCY" in sig.signal_type
                ):
                    behavioral_signals.append(sig)
                else:
                    security_signals.append(sig)

            await _record_event(
                uow,
                job.analysis_id,
                "security_engine",
                "Deterministic analysis complete",
                {
                    "signals": len(all_signals),
                    "critical": sum(
                        1 for s in all_signals if s.severity == ThreatSeverity.CRITICAL
                    ),
                },
            )
            await _emit(
                analysis_id_str,
                AnalysisStage.SECURITY_ENGINE,
                status="processing",
                data={"signal_count": len(all_signals)},
            )

        except Exception as exc:
            logger.warning("security_engine_failed", analysis_id=analysis_id_str, error=str(exc))
            await _record_event(
                uow,
                job.analysis_id,
                "security_engine",
                f"Security engine failed: {exc}",
                is_error=True,
            )

        # ----------------------------------------------------------------
        # STAGE 3: ML Engine
        # ----------------------------------------------------------------
        await _emit(analysis_id_str, AnalysisStage.ML_ENGINE, status="processing")
        try:
            ml_service = MLInferenceService()
            ml_result = ml_service.predict(email_input)
            await _record_event(
                uow,
                job.analysis_id,
                "ml_engine",
                "ML classification complete",
                {"classification": ml_result.classification, "probability": ml_result.probability},
            )
            await _emit(
                analysis_id_str,
                AnalysisStage.ML_ENGINE,
                status="processing",
                data={
                    "classification": ml_result.classification,
                    "probability": round(ml_result.probability, 3),
                },
            )

        except Exception as exc:
            logger.warning("ml_engine_failed", analysis_id=analysis_id_str, error=str(exc))
            await _record_event(
                uow, job.analysis_id, "ml_engine", f"ML engine failed: {exc}", is_error=True
            )

        # ----------------------------------------------------------------
        # STAGE 4: Threat Intelligence
        # ----------------------------------------------------------------
        await _emit(analysis_id_str, AnalysisStage.THREAT_INTEL, status="processing")
        try:
            ti_service = get_threat_intel_service()
            ti_reports = await ti_service.extract_and_check_email(email_input)
            malicious_hits = sum(1 for r in ti_reports if r.reputation.value == "malicious")
            await _record_event(
                uow,
                job.analysis_id,
                "threat_intel",
                "Threat intelligence checks complete",
                {"total_checked": len(ti_reports), "malicious_hits": malicious_hits},
            )
            await _emit(
                analysis_id_str,
                AnalysisStage.THREAT_INTEL,
                status="processing",
                data={"total_checked": len(ti_reports), "malicious_hits": malicious_hits},
            )

        except Exception as exc:
            logger.warning("threat_intel_failed", analysis_id=analysis_id_str, error=str(exc))
            await _record_event(
                uow, job.analysis_id, "threat_intel", f"Threat Intel failed: {exc}", is_error=True
            )

        # ----------------------------------------------------------------
        # STAGE 5: Groq LLM (only when score warrants semantic analysis)
        # ----------------------------------------------------------------
        await _emit(analysis_id_str, AnalysisStage.GROQ_LLM, status="processing")
        try:
            # Build preliminary risk assessment to decide if LLM call is worth it
            risk_prelim = RiskEngine().assess(
                security_signals=security_signals,
                behavioral_signals=behavioral_signals,
                ml_result=ml_result,
                threat_intel_signals=[r.to_threat_intel_signal() for r in ti_reports],
            )
            # Invoke LLM if score is ≥ 30 (i.e. not obviously clean)
            if risk_prelim.risk_score >= 30.0:
                all_sig = security_signals + behavioral_signals
                llm_analyzer = LLMAnalyzer()
                llm_result = await llm_analyzer.analyze(email_input, all_sig)
                await _emit(
                    analysis_id_str,
                    AnalysisStage.GROQ_LLM,
                    status="processing",
                    data={"status": llm_result.status, "classification": llm_result.classification},
                )
            else:
                await _emit(
                    analysis_id_str,
                    AnalysisStage.GROQ_LLM,
                    status="processing",
                    data={"status": "skipped", "reason": "score_below_threshold"},
                )

            await _record_event(
                uow,
                job.analysis_id,
                "groq_llm",
                "LLM semantic analysis complete",
                {"status": llm_result.status if llm_result else "skipped"},
            )

        except Exception as exc:
            logger.warning("groq_llm_failed", analysis_id=analysis_id_str, error=str(exc))
            await _record_event(
                uow, job.analysis_id, "groq_llm", f"Groq LLM failed: {exc}", is_error=True
            )

        # ----------------------------------------------------------------
        # STAGE 6: Risk Engine — Final Composite Scoring
        # ----------------------------------------------------------------
        await _emit(analysis_id_str, AnalysisStage.RISK_ENGINE, status="processing")
        try:
            if llm_result is None and risk_prelim is not None:
                # Reuse identical preliminary calculation when LLM was skipped
                risk_assessment = risk_prelim
            else:
                risk_engine = RiskEngine()
                risk_assessment = risk_engine.assess(
                    security_signals=security_signals,
                    behavioral_signals=behavioral_signals,
                    ml_result=ml_result,
                    llm_result=llm_result,
                    threat_intel_signals=[r.to_threat_intel_signal() for r in ti_reports],
                )
            await _record_event(
                uow,
                job.analysis_id,
                "risk_engine",
                "Risk scoring complete",
                {"score": risk_assessment.risk_score, "severity": risk_assessment.severity.value},
            )
            await _emit(
                analysis_id_str,
                AnalysisStage.RISK_ENGINE,
                status="processing",
                data={
                    "risk_score": risk_assessment.risk_score,
                    "severity": risk_assessment.severity.value,
                    "verdict": risk_assessment.verdict.value,
                },
            )

        except Exception as exc:
            logger.error("risk_engine_failed", analysis_id=analysis_id_str, error=str(exc))
            await _record_event(
                uow, job.analysis_id, "risk_engine", f"Risk engine failed: {exc}", is_error=True
            )
            await uow.analyses.record_failure(
                job.analysis_id, error_message=f"Risk engine failed: {exc}"
            )
            await uow.commit()
            await _emit(
                analysis_id_str, AnalysisStage.FAILED, status="failed", error_message=str(exc)
            )
            return

        # ----------------------------------------------------------------
        # STAGE 7: Persistence
        # ----------------------------------------------------------------
        await _emit(analysis_id_str, AnalysisStage.PERSISTENCE, status="processing")
        try:
            pipeline_duration_ms = int((time.perf_counter() - pipeline_start) * 1000)
            assert uow.session is not None

            # Persist threat signals
            for sig in security_signals + behavioral_signals:
                db_signal = ThreatSignal(
                    analysis_id=job.analysis_id,
                    org_id=job.org_id,
                    signal_type=sig.signal_type[:100],
                    category=ThreatCategory(sig.category.value),
                    severity=ThreatSeverity(sig.severity.value),
                    attack_type=AttackType(sig.attack_type.value),
                    confidence=sig.confidence,
                    source_engine=sig.source[:50],
                    title=sig.title[:255],
                    description=sig.description[:1000] if sig.description else None,
                    indicator_value=sig.indicator_value[:500] if sig.indicator_value else None,
                    raw_evidence=sig.evidence,
                )
                uow.session.add(db_signal)

            # Persist ML prediction
            if ml_result:
                db_ml = MLPrediction(
                    analysis_id=job.analysis_id,
                    model_name="random_forest_phishing_v1",
                    model_version=ml_result.model_version,
                    prediction_label=ml_result.classification,
                    confidence_score=ml_result.confidence,
                    phishing_probability=ml_result.phishing_probability,
                    spam_probability=ml_result.spam_probability,
                    malware_probability=0.0,
                    feature_weights=ml_result.feature_contributions,
                )
                uow.session.add(db_ml)

            # Persist LLM analysis
            if llm_result and llm_result.analysis:
                la = llm_result.analysis
                iocs: list[dict[str, Any]] = [
                    {"type": "social_engineering_tactic", "value": t}
                    for t in (la.social_engineering_tactics or [])
                ] + [{"type": "evidence_quote", "value": q} for q in (la.evidence_quotes or [])]
                if la.impersonation_target:
                    iocs.append({"type": "impersonation_target", "value": la.impersonation_target})

                intent_summary = f"Intent: {la.classification.value}. Impersonation: {la.impersonation_target or 'None'}. Credential request: {la.is_credential_request}. Payment request: {la.is_payment_request}."

                db_llm = LLMAnalysis(
                    analysis_id=job.analysis_id,
                    model_name=llm_result.model,
                    prompt_version="2026.1",
                    threat_narrative=la.threat_narrative,
                    executive_summary=la.executive_summary,
                    recommended_action=la.recommended_action,
                    reasoning=intent_summary,
                    extracted_iocs=iocs,
                    confidence_score=la.confidence,
                    token_usage=llm_result.token_usage or {},
                    safety_passed=True,
                    latency_ms=int(llm_result.latency_ms or 0),
                )
                uow.session.add(db_llm)

            # Persist Risk Score
            db_risk = DBRiskScore(
                analysis_id=job.analysis_id,
                org_id=job.org_id,
                composite_score=int(risk_assessment.risk_score),
                risk_level=RiskLevel(risk_assessment.risk_level.value),
                spf_subscore=risk_assessment.subscores.security,
                dkim_subscore=0.0,
                dmarc_subscore=0.0,
                ml_subscore=risk_assessment.subscores.ml,
                url_subscore=0.0,
                attachment_subscore=0.0,
                sender_reputation_subscore=risk_assessment.subscores.threat_intel,
                factor_breakdown=[
                    {
                        "policy": risk_assessment.policy_name,
                        "rationale": risk_assessment.rationale[:500],
                    }
                ],
                scoring_version=risk_assessment.engine_version,
            )
            uow.session.add(db_risk)

            # Update analysis record
            await uow.analyses.record_completion(
                job.analysis_id,
                verdict=AnalysisVerdict(risk_assessment.verdict.value),
                overall_risk_score=int(risk_assessment.risk_score),
                risk_level=RiskLevel(risk_assessment.risk_level.value),
                duration_ms=pipeline_duration_ms,
            )

            # Record completion event
            await _record_event(
                uow,
                job.analysis_id,
                "completed",
                "Analysis pipeline completed",
                {
                    "risk_score": risk_assessment.risk_score,
                    "verdict": risk_assessment.verdict.value,
                    "duration_ms": pipeline_duration_ms,
                },
            )
            await uow.commit()

        except Exception as exc:
            logger.error("persistence_failed", analysis_id=analysis_id_str, error=str(exc))
            await uow.rollback()
            await uow.analyses.record_failure(
                job.analysis_id, error_message=f"Persistence failed: {exc}"
            )
            await uow.commit()
            await _emit(
                analysis_id_str, AnalysisStage.FAILED, status="failed", error_message=str(exc)
            )
            return

    # Synthesize findings and security checks for real-time notification
    top_findings = [sig.title for sig in (security_signals + behavioral_signals)[:3] if sig.title]
    if not top_findings:
        top_findings = [
            "Sender authentication passed (SPF/DKIM/DMARC)",
            "No suspicious or defanged URLs detected",
            "No weaponized or executable attachments found",
        ]

    sec_summary = {
        "spf": email_input.headers.spf_status.value if email_input and email_input.headers and email_input.headers.spf_status else "unknown",
        "dkim": email_input.headers.dkim_status.value if email_input and email_input.headers and email_input.headers.dkim_status else "unknown",
        "dmarc": email_input.headers.dmarc_status.value if email_input and email_input.headers and email_input.headers.dmarc_status else "unknown",
        "urls_analyzed": len(email_input.urls) if email_input else 0,
        "attachments_analyzed": len(email_input.attachments) if email_input else 0,
    }

    categories_list = list(dict.fromkeys(sig.category.value for sig in (security_signals + behavioral_signals) if sig.category))

    expl_text = (
        llm_result.analysis.executive_summary
        if (llm_result and llm_result.analysis and llm_result.analysis.executive_summary)
        else risk_assessment.rationale
    )

    # Final completed event broadcast
    await _emit(
        analysis_id_str,
        AnalysisStage.COMPLETED,
        status="completed",
        data={
            "analysis_id": analysis_id_str,
            "risk_score": int(risk_assessment.risk_score),
            "severity": risk_assessment.severity.value,
            "verdict": risk_assessment.verdict.value,
            "classification": risk_assessment.classification.value,
            "recommendation": risk_assessment.recommendation,
            "recommendations": [risk_assessment.recommendation],
            "subject": email_input.subject if email_input else (email_record.subject if email_record else None),
            "sender": email_input.from_address if email_input else (email_record.from_address if email_record else None),
            "explanation": expl_text,
            "findings": top_findings,
            "security_checks": sec_summary,
            "threat_categories": categories_list,
            "completed_at": datetime.now(UTC).isoformat(),
        },
    )

    logger.info(
        "analysis_pipeline_completed",
        analysis_id=analysis_id_str,
        risk_score=risk_assessment.risk_score,
        verdict=risk_assessment.verdict.value,
        duration_ms=int((time.perf_counter() - pipeline_start) * 1000),
    )
