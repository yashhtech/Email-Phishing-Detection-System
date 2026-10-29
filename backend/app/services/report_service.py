"""Security Analysis Report generation and sanitization service.

Compiles forensic telemetry across security analyzers, machine learning,
Groq LLM semantic narratives, and threat intelligence feeds into authoritative
executive and technical reports.

Guarantees:
- Secrets, tokens, and internal API keys are strictly excluded/redacted.
- Deterministic security evidence is clearly differentiated from AI inferences.
- Output can be serialized as structured JSON or rendered into a print-ready HTML layout.
"""

from __future__ import annotations

import html
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from app.api.schemas.report import (
    AnalysisReportResponse,
    ReportClassification,
    ReportEmailMetadata,
    ReportEvidenceItem,
    ReportGroqAnalysis,
    ReportMLAnalysis,
    ReportRiskScore,
    ReportSecuritySignal,
    ReportThreatIntelligence,
    ReportTimestamps,
)
from app.infrastructure.db.models.analysis import Analysis
from app.infrastructure.db.models.enums import (
    AnalysisStatus,
    AnalysisVerdict,
    AttackType,
    RiskLevel,
    ThreatSeverity,
)

# ---------------------------------------------------------------------------
# Secret & Key Sanitization Rules
# ---------------------------------------------------------------------------

_SENSITIVE_KEY_PATTERNS = re.compile(
    r"(api_?key|secret|password|token|bearer|credential|authorization|private_key)",
    re.IGNORECASE,
)

_SENSITIVE_VAL_PATTERNS = re.compile(
    r"(gsk_[a-zA-Z0-9_-]{20,}|Bearer\s+[a-zA-Z0-9_\-\.]{15,}|[a-f0-9]{32,64})",
    re.IGNORECASE,
)


def sanitize_value(val: Any) -> Any:
    """Recursively sanitize data to strip any API keys or credentials."""
    if isinstance(val, dict):
        sanitized: dict[str, Any] = {}
        for k, v in val.items():
            if _SENSITIVE_KEY_PATTERNS.search(k):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_value(v)
        return sanitized
    if isinstance(val, list):
        return [sanitize_value(item) for item in val]
    if isinstance(val, str):
        # Scrub potential API keys like Groq or VirusTotal tokens
        if "gsk_" in val or "Bearer " in val:
            return _SENSITIVE_VAL_PATTERNS.sub("[REDACTED_KEY]", val)
        return val
    return val


def _determine_why_it_matters(category: str, severity: str, attack_type: str) -> str:
    """Provide clear, non-technical context on why a specific finding matters."""
    cat_lower = category.lower()
    sev_lower = severity.lower()
    atk_lower = attack_type.lower()

    if "authentication" in cat_lower or "spf" in cat_lower or "dmarc" in cat_lower:
        return (
            "Email sender authentication checks failed. Attackers frequently forge headers "
            "to impersonate trusted executives, partners, or vendors."
        )
    if "credential" in cat_lower or "credential" in atk_lower:
        return (
            "The email attempts to harvest corporate or personal login credentials using deceptive "
            "lookalike portals or urgency tactics."
        )
    if "malware" in cat_lower or "ransomware" in atk_lower:
        return (
            "Payload contains malicious scripts or file types known to drop malware or execute unauthorized "
            "code on the victim's endpoint."
        )
    if "business_email_compromise" in cat_lower or "bec" in atk_lower or "whaling" in atk_lower:
        return (
            "Social engineering patterns match Business Email Compromise (BEC), aimed at illicit wire transfers "
            "or data exfiltration via authority impersonation."
        )
    if "phishing" in cat_lower or "phishing" in atk_lower:
        return (
            "Message contains deceptive lures designed to trick the recipient into divulging sensitive "
            "information or clicking malicious links."
        )
    if sev_lower in ("critical", "high"):
        return "Severe security anomaly detected that indicates active compromise attempt."
    return "Security indicator flagged for anomalous behavior or policy deviation."


class ReportService:
    """Service for building and formatting security analysis reports."""

    ENGINE_VERSION = "1.0.0"
    DEFAULT_SCORING_VERSION = "1.0"

    @classmethod
    def build_report(
        cls,
        analysis: Analysis,
        *,
        actor_email: str | None = None,
        actor_user_id: uuid.UUID | None = None,
        org_name: str | None = None,
    ) -> AnalysisReportResponse:
        """Compile a comprehensive AnalysisReportResponse from an Analysis ORM record."""
        now = datetime.now(UTC)
        report_id = uuid.uuid4()

        # 1. Email Metadata
        email = analysis.email
        header = email.header if email else None
        attachments = email.attachments if email else []
        urls = email.urls if email else []

        spf_st = (
            header.spf_verdict.value
            if header and header.spf_verdict
            else (
                analysis.risk_score.factor_breakdown.get("spf_status")
                if analysis.risk_score
                and isinstance(analysis.risk_score.factor_breakdown, dict)
                else None
            )
        )
        dkim_st = (
            header.dkim_verdict.value
            if header and header.dkim_verdict
            else (
                analysis.risk_score.factor_breakdown.get("dkim_status")
                if analysis.risk_score
                and isinstance(analysis.risk_score.factor_breakdown, dict)
                else None
            )
        )
        dmarc_st = (
            header.dmarc_verdict.value
            if header and header.dmarc_verdict
            else (
                analysis.risk_score.factor_breakdown.get("dmarc_status")
                if analysis.risk_score
                and isinstance(analysis.risk_score.factor_breakdown, dict)
                else None
            )
        )

        email_meta = ReportEmailMetadata(
            email_id=str(email.id) if email else "unknown",
            message_id=email.message_id if email else None,
            from_address=email.from_address if email else "unknown",
            from_domain=email.from_domain if email else None,
            to_addresses=list(email.to_addresses) if email and email.to_addresses else [],
            cc_addresses=list(email.cc_addresses) if email and email.cc_addresses else [],
            reply_to=email.reply_to if email else None,
            subject=email.subject if email else None,
            received_at=email.received_at if email else now,
            has_attachments=bool(email.has_attachments if email else False),
            attachment_count=len(attachments)
            if attachments
            else (email.attachment_count if email else 0),
            url_count=len(urls),
            spf_status=spf_st,
            dkim_status=dkim_st,
            dmarc_status=dmarc_st,
            return_path=header.return_path if header else None,
        )

        # 2. Risk Score
        rs = analysis.risk_score
        scoring_ver = rs.scoring_version if rs else cls.DEFAULT_SCORING_VERSION
        risk_score = ReportRiskScore(
            overall_risk_score=analysis.overall_risk_score or 0,
            risk_level=analysis.risk_level.value if analysis.risk_level else RiskLevel.SAFE.value,
            composite_score=rs.composite_score if rs else (analysis.overall_risk_score or 0),
            scoring_version=scoring_ver,
            spf_subscore=rs.spf_subscore if rs else 0.0,
            dkim_subscore=rs.dkim_subscore if rs else 0.0,
            dmarc_subscore=rs.dmarc_subscore if rs else 0.0,
            ml_subscore=rs.ml_subscore if rs else 0.0,
            url_subscore=rs.url_subscore if rs else 0.0,
            attachment_subscore=rs.attachment_subscore if rs else 0.0,
            sender_reputation_subscore=rs.sender_reputation_subscore if rs else 0.0,
            factor_breakdown=sanitize_value(rs.factor_breakdown)
            if rs and isinstance(rs.factor_breakdown, list)
            else None,
        )

        # 3. Classification
        signals = analysis.threat_signals or []
        primary_attack: str = AttackType.UNKNOWN.value
        if signals:
            # Pick highest severity attack type
            primary_attack = signals[0].attack_type.value

        verdict_val = (
            analysis.verdict.value if analysis.verdict else AnalysisVerdict.CLEAN.value
        )
        status_val = (
            "completed"
            if analysis.status == AnalysisStatus.COMPLETE
            else analysis.status.value
        )

        classification = ReportClassification(
            verdict=verdict_val,
            status=status_val,
            primary_attack_type=primary_attack,
            severity=analysis.risk_level.value if analysis.risk_level else ThreatSeverity.LOW.value,
            confidence=round(
                max([s.confidence for s in signals] or [0.95]),
                2,
            ),
        )

        # 4. Security Signals
        report_signals: list[ReportSecuritySignal] = []
        for s in signals:
            report_signals.append(
                ReportSecuritySignal(
                    id=str(s.id),
                    signal_type=s.signal_type,
                    category=s.category.value if hasattr(s.category, "value") else str(s.category),
                    severity=s.severity.value if hasattr(s.severity, "value") else str(s.severity),
                    attack_type=s.attack_type.value
                    if hasattr(s.attack_type, "value")
                    else str(s.attack_type),
                    confidence=round(s.confidence, 4),
                    source=s.source_engine,
                    title=s.title,
                    description=s.description or "",
                    indicator_value=sanitize_value(s.indicator_value),
                )
            )

        # 5. ML Analysis
        ml = analysis.ml_prediction
        ml_analysis: ReportMLAnalysis | None = None
        if ml:
            ml_analysis = ReportMLAnalysis(
                model_name=ml.model_name,
                model_version=ml.model_version,
                classification=ml.prediction_label,
                confidence=round(ml.confidence_score, 4),
                phishing_probability=round(ml.phishing_probability, 4),
                spam_probability=round(ml.spam_probability, 4),
                malware_probability=round(ml.malware_probability, 4),
                latency_ms=ml.latency_ms,
            )

        # 6. Groq Analysis (Sanitized)
        llm = analysis.llm_analysis
        groq_analysis: ReportGroqAnalysis | None = None
        if llm:
            groq_analysis = ReportGroqAnalysis(
                model_name=llm.model_name,
                prompt_version=llm.prompt_version,
                threat_narrative=sanitize_value(llm.threat_narrative),
                executive_summary=sanitize_value(llm.executive_summary),
                recommended_action=llm.recommended_action,
                reasoning=sanitize_value(llm.reasoning),
                extracted_iocs=sanitize_value(llm.extracted_iocs or []),
                safety_passed=llm.safety_passed,
                confidence_score=round(llm.confidence_score, 4),
                latency_ms=llm.latency_ms,
            )

        # 7. Threat Intelligence (Sanitized, NO provider API keys or bearer tokens)
        ti_results = analysis.threat_intel_results or []
        report_ti: list[ReportThreatIntelligence] = []
        for ti in ti_results:
            report_ti.append(
                ReportThreatIntelligence(
                    indicator_type=ti.indicator_type,
                    indicator_value=sanitize_value(ti.indicator_value),
                    provider=ti.provider,
                    reputation=ti.reputation_verdict.value
                    if hasattr(ti.reputation_verdict, "value")
                    else str(ti.reputation_verdict),
                    threat_score=ti.threat_score,
                    tags=sanitize_value(ti.tags or []),
                    last_checked_at=ti.last_checked_at,
                )
            )

        # 8. Evidence Items
        evidence: list[ReportEvidenceItem] = []
        for s in signals:
            cat_str = s.category.value if hasattr(s.category, "value") else str(s.category)
            sev_str = s.severity.value if hasattr(s.severity, "value") else str(s.severity)
            atk_str = (
                s.attack_type.value if hasattr(s.attack_type, "value") else str(s.attack_type)
            )
            evidence.append(
                ReportEvidenceItem(
                    title=s.title,
                    severity=sev_str,
                    source=s.source_engine,
                    category=cat_str,
                    attack_type=atk_str,
                    description=s.description or "",
                    indicator_value=sanitize_value(s.indicator_value),
                    confidence=round(s.confidence, 4),
                    why_it_matters=_determine_why_it_matters(cat_str, sev_str, atk_str),
                )
            )

        # 9. Timestamps
        timestamps = ReportTimestamps(
            email_received_at=email.received_at if email else None,
            analysis_started_at=analysis.started_at,
            analysis_completed_at=analysis.completed_at,
            report_generated_at=now,
            duration_ms=analysis.duration_ms,
        )

        # 10. Actor attribution
        gen_by = actor_email or (f"User ID: {actor_user_id}" if actor_user_id else "Security Analyst")

        return AnalysisReportResponse(
            report_id=report_id,
            analysis_id=analysis.id,
            org_id=analysis.org_id,
            org_name=org_name,
            engine_version=cls.ENGINE_VERSION,
            scoring_version=scoring_ver,
            classification=classification,
            risk_score=risk_score,
            email_metadata=email_meta,
            security_signals=report_signals,
            ml_analysis=ml_analysis,
            groq_analysis=groq_analysis,
            threat_intelligence=report_ti,
            evidence=evidence,
            timestamps=timestamps,
            generated_by=gen_by,
        )

    @classmethod
    def render_html(cls, report: AnalysisReportResponse) -> str:
        """Render a clean, publication-ready light-themed HTML report.

        Includes print-specific CSS (@media print) for direct export to PDF.
        """
        # Styling color mappings
        score = report.risk_score.overall_risk_score
        risk_level = report.risk_score.risk_level.lower()

        badge_colors = {
            "critical": ("#dc2626", "#fef2f2", "#fca5a5"),
            "high": ("#ea580c", "#fff7ed", "#fdba74"),
            "medium": ("#d97706", "#fffbeb", "#fcd34d"),
            "low": ("#16a34a", "#f0fdf4", "#86efac"),
            "safe": ("#059669", "#ecfdf5", "#6ee7b7"),
            "clean": ("#059669", "#ecfdf5", "#6ee7b7"),
            "suspicious": ("#d97706", "#fffbeb", "#fcd34d"),
            "malicious": ("#dc2626", "#fef2f2", "#fca5a5"),
        }

        fg, bg, border = badge_colors.get(risk_level, ("#4b5563", "#f9fafb", "#e5e7eb"))

        # Format helpers
        def esc(val: Any) -> str:
            return html.escape(str(val or "—"))

        def dt_str(d: datetime | None) -> str:
            if not d:
                return "—"
            return d.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Evidence rows HTML
        evidence_html = ""
        for ev in report.evidence:
            ev_fg, ev_bg, ev_border = badge_colors.get(ev.severity.lower(), ("#4b5563", "#f9fafb", "#e5e7eb"))
            evidence_html += f"""
            <div class="evidence-card">
              <div class="evidence-header">
                <span class="badge" style="color: {ev_fg}; background: {ev_bg}; border-color: {ev_border};">
                  {esc(ev.severity.upper())}
                </span>
                <span class="source-tag">{esc(ev.source)}</span>
                <span class="attack-type">{esc(ev.attack_type.replace('_', ' '))}</span>
                <span class="confidence">Confidence: {int(ev.confidence * 100)}%</span>
              </div>
              <h4 class="evidence-title">{esc(ev.title)}</h4>
              <p class="evidence-desc">{esc(ev.description)}</p>
              {f'<div class="indicator-box"><strong>Indicator:</strong> <code>{esc(ev.indicator_value)}</code></div>' if ev.indicator_value else ''}
              <div class="why-box">
                <span class="why-label">Why it matters:</span> {esc(ev.why_it_matters)}
              </div>
            </div>
            """

        if not evidence_html:
            evidence_html = "<p class='empty-text'>No adverse security evidence recorded. All baseline security checks passed.</p>"

        # TI rows HTML
        ti_html = ""
        for ti in report.threat_intelligence:
            ti_fg, ti_bg, ti_border = badge_colors.get(ti.reputation.lower(), ("#4b5563", "#f9fafb", "#e5e7eb"))
            ti_html += f"""
            <tr>
              <td><code>{esc(ti.indicator_value)}</code></td>
              <td><span class="type-tag">{esc(ti.indicator_type)}</span></td>
              <td><strong>{esc(ti.provider)}</strong></td>
              <td>
                <span class="badge" style="color: {ti_fg}; background: {ti_bg}; border-color: {ti_border};">
                  {esc(ti.reputation.upper())}
                </span>
              </td>
              <td>{esc(ti.threat_score) if ti.threat_score is not None else '—'}</td>
              <td>{esc(", ".join(ti.tags)) if ti.tags else '—'}</td>
              <td>{dt_str(ti.last_checked_at)}</td>
            </tr>
            """

        if not ti_html:
            ti_html = "<tr><td colspan='7' class='text-center empty-text'>No external indicators queried or threat intel returned clean.</td></tr>"

        # ML section HTML
        ml_html = ""
        if report.ml_analysis:
            ml = report.ml_analysis
            ml_html = f"""
            <div class="card grid-2">
              <div>
                <p class="section-label">Model Classification</p>
                <div class="big-metric">{esc(ml.classification.title())}</div>
                <div class="meta-row">
                  <span>Model: <strong>{esc(ml.model_name)}</strong></span>
                  <span>Version: <code>{esc(ml.model_version)}</code></span>
                  <span>Confidence: <strong>{int(ml.confidence * 100)}%</strong></span>
                </div>
              </div>
              <div>
                <p class="section-label">Calibrated Class Probabilities</p>
                <div class="prob-row">
                  <span>Phishing:</span>
                  <div class="bar-container"><div class="bar bar-phish" style="width: {int(ml.phishing_probability * 100)}%;"></div></div>
                  <span class="prob-val">{ml.phishing_probability * 100:.1f}%</span>
                </div>
                <div class="prob-row">
                  <span>Malware:</span>
                  <div class="bar-container"><div class="bar bar-malware" style="width: {int(ml.malware_probability * 100)}%;"></div></div>
                  <span class="prob-val">{ml.malware_probability * 100:.1f}%</span>
                </div>
                <div class="prob-row">
                  <span>Spam:</span>
                  <div class="bar-container"><div class="bar bar-spam" style="width: {int(ml.spam_probability * 100)}%;"></div></div>
                  <span class="prob-val">{ml.spam_probability * 100:.1f}%</span>
                </div>
              </div>
            </div>
            """
        else:
            ml_html = "<div class='card'><p class='empty-text'>Machine learning model prediction not applicable or bypassed.</p></div>"

        # Groq section HTML
        groq_html = ""
        if report.groq_analysis:
            g = report.groq_analysis
            groq_html = f"""
            <div class="card groq-card">
              <div class="card-header">
                <span class="ai-badge">AI Semantic Analysis • {esc(g.model_name)}</span>
                <span class="meta-item">Prompt Version: <code>{esc(g.prompt_version)}</code></span>
                <span class="meta-item">Confidence: <strong>{int(g.confidence_score * 100)}%</strong></span>
              </div>
              <div class="groq-content">
                {f'<div class="exec-summary"><strong>Executive Summary:</strong> {esc(g.executive_summary)}</div>' if g.executive_summary else ''}
                <div class="narrative"><strong>Threat Narrative:</strong><br>{esc(g.threat_narrative)}</div>
                {f'<div class="reasoning"><strong>Reasoning Steps:</strong><br>{esc(g.reasoning)}</div>' if g.reasoning else ''}
                <div class="recommendation-box">
                  <strong>Recommended Action:</strong> <span class="action-tag">{esc(g.recommended_action.upper())}</span>
                </div>
              </div>
            </div>
            """
        else:
            groq_html = "<div class='card'><p class='empty-text'>Groq LLM semantic reasoning was not triggered for this email (score below semantic threshold).</p></div>"

        # Assemble Full Document
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Analysis Report - {esc(report.analysis_id)}</title>
  <style>
    /* Light theme typography and tokens */
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 32px;
      color: #1e293b;
      background-color: #f8fafc;
      line-height: 1.5;
    }}
    .container {{
      max-width: 900px;
      margin: 0 auto;
      background: #ffffff;
      padding: 40px;
      border-radius: 16px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
      border: 1px solid #e2e8f0;
    }}
    .header-bar {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 2px solid #e2e8f0;
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    .title-group h1 {{
      font-size: 24px;
      margin: 0 0 4px 0;
      color: #0f172a;
      letter-spacing: -0.02em;
    }}
    .subtitle {{
      font-size: 13px;
      color: #64748b;
      margin: 0;
    }}
    .confidential-stamp {{
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.08em;
      color: #dc2626;
      border: 1px solid #fca5a5;
      background: #fef2f2;
      padding: 4px 8px;
      border-radius: 6px;
      text-transform: uppercase;
    }}
    .verdict-banner {{
      display: flex;
      gap: 24px;
      align-items: center;
      padding: 24px;
      border-radius: 12px;
      margin-bottom: 28px;
      border: 2px solid {border};
      background: {bg};
    }}
    .score-circle {{
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      width: 80px;
      height: 80px;
      border-radius: 12px;
      background: #ffffff;
      border: 2px solid {border};
      flex-shrink: 0;
    }}
    .score-num {{
      font-size: 32px;
      font-weight: 800;
      color: {fg};
      line-height: 1;
    }}
    .score-lbl {{
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      color: #64748b;
      margin-top: 4px;
    }}
    .verdict-info h2 {{
      margin: 0 0 4px 0;
      font-size: 20px;
      color: {fg};
      text-transform: uppercase;
      letter-spacing: -0.01em;
    }}
    .verdict-info p {{
      margin: 0;
      font-size: 13px;
      color: #475569;
    }}
    .card {{
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 24px;
    }}
    .section-title {{
      font-size: 15px;
      font-weight: 700;
      color: #0f172a;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin: 0 0 16px 0;
      border-bottom: 1px solid #f1f5f9;
      padding-bottom: 8px;
    }}
    .meta-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    .meta-table th {{
      text-align: left;
      width: 150px;
      color: #64748b;
      padding: 6px 0;
      font-weight: 600;
    }}
    .meta-table td {{
      padding: 6px 0;
      color: #1e293b;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      font-size: 11px;
      font-weight: 700;
      border-radius: 6px;
      border: 1px solid transparent;
      letter-spacing: 0.02em;
    }}
    .type-tag {{
      display: inline-block;
      padding: 2px 6px;
      font-size: 11px;
      font-weight: 600;
      background: #f1f5f9;
      color: #475569;
      border-radius: 4px;
      text-transform: uppercase;
    }}
    .grid-2 {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
    }}
    .big-metric {{
      font-size: 26px;
      font-weight: 800;
      color: #0f172a;
      margin-bottom: 8px;
    }}
    .meta-row {{
      font-size: 12px;
      color: #64748b;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .prob-row {{
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      margin-bottom: 8px;
    }}
    .prob-row span:first-child {{ width: 70px; color: #475569; }}
    .bar-container {{
      flex: 1;
      height: 8px;
      background: #f1f5f9;
      border-radius: 4px;
      overflow: hidden;
    }}
    .bar {{ height: 100%; border-radius: 4px; }}
    .bar-phish {{ background: #dc2626; }}
    .bar-malware {{ background: #ea580c; }}
    .bar-spam {{ background: #d97706; }}
    .prob-val {{ width: 45px; text-align: right; font-weight: 700; }}
    .groq-card {{
      border-left: 4px solid #7c3aed;
      background: #faf5ff;
    }}
    .card-header {{
      display: flex;
      justify-content: space-between;
      margin-bottom: 12px;
      font-size: 12px;
    }}
    .ai-badge {{
      background: #7c3aed;
      color: #ffffff;
      padding: 2px 8px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 11px;
    }}
    .groq-content {{ font-size: 13px; color: #334155; }}
    .exec-summary {{ margin-bottom: 10px; font-size: 13.5px; line-height: 1.6; color: #1e293b; }}
    .narrative {{ margin-bottom: 10px; white-space: pre-wrap; }}
    .reasoning {{ margin-bottom: 10px; font-style: italic; color: #475569; }}
    .recommendation-box {{
      margin-top: 12px;
      padding: 8px 12px;
      background: #ffffff;
      border: 1px solid #ddd6fe;
      border-radius: 6px;
      display: inline-block;
    }}
    .action-tag {{
      color: #6d28d9;
      font-weight: 800;
      letter-spacing: 0.05em;
    }}
    table.data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }}
    table.data-table th {{
      background: #f8fafc;
      color: #64748b;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
      padding: 8px;
      border-bottom: 2px solid #e2e8f0;
      text-align: left;
    }}
    table.data-table td {{
      padding: 8px;
      border-bottom: 1px solid #f1f5f9;
      color: #1e293b;
    }}
    .evidence-card {{
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 12px;
      background: #ffffff;
    }}
    .evidence-header {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
    }}
    .source-tag {{
      background: #f0fdfa;
      color: #0f766e;
      border: 1px solid #ccfbf1;
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }}
    .attack-type {{
      color: #64748b;
      font-size: 11px;
      font-weight: 600;
      text-transform: capitalize;
    }}
    .confidence {{
      margin-left: auto;
      font-size: 11px;
      color: #94a3b8;
    }}
    .evidence-title {{
      margin: 0 0 4px 0;
      font-size: 14px;
      color: #0f172a;
    }}
    .evidence-desc {{
      margin: 0 0 8px 0;
      font-size: 12.5px;
      color: #475569;
    }}
    .indicator-box {{
      font-size: 12px;
      background: #f8fafc;
      padding: 4px 8px;
      border-radius: 4px;
      margin-bottom: 6px;
    }}
    .why-box {{
      font-size: 12px;
      color: #0369a1;
      background: #f0f9ff;
      border-left: 3px solid #0284c7;
      padding: 6px 10px;
      border-radius: 0 4px 4px 0;
    }}
    .why-label {{ font-weight: 700; color: #0284c7; }}
    .footer-audit {{
      margin-top: 36px;
      padding-top: 16px;
      border-top: 1px solid #e2e8f0;
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      color: #94a3b8;
    }}
    .print-actions {{
      margin-bottom: 20px;
      text-align: right;
    }}
    .print-btn {{
      background: #7c3aed;
      color: #ffffff;
      border: none;
      padding: 8px 16px;
      border-radius: 8px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
    }}
    .print-btn:hover {{ background: #6d28d9; }}
    .empty-text {{ color: #94a3b8; font-size: 13px; font-style: italic; }}

    /* Print styles */
    @media print {{
      body {{ background: #ffffff; padding: 0; }}
      .container {{ border: none; box-shadow: none; padding: 0; max-width: 100%; }}
      .print-actions {{ display: none; }}
      .evidence-card {{ page-break-inside: avoid; }}
      .card {{ page-break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="print-actions">
      <button class="print-btn" onclick="window.print()">Print / Export PDF</button>
    </div>

    <div class="header-bar">
      <div class="title-group">
        <h1>Email Security Incident Report</h1>
        <p class="subtitle">
          Report ID: <code>{esc(report.report_id)}</code> &bull; Engine v{esc(report.engine_version)} (Scoring v{esc(report.scoring_version)})
        </p>
      </div>
      <div class="confidential-stamp">
        {esc(report.confidentiality)}
      </div>
    </div>

    <!-- Overall Verdict & Risk Score -->
    <div class="verdict-banner">
      <div class="score-circle">
        <span class="score-num">{score}</span>
        <span class="score-lbl">Risk Score</span>
      </div>
      <div class="verdict-info">
        <h2>Verdict: {esc(report.classification.verdict.upper())} ({esc(risk_level.upper())} RISK)</h2>
        <p>Primary Threat Classification: <strong>{esc(report.classification.primary_attack_type.replace('_', ' ').title())}</strong> &bull; Analysis Status: {esc(report.classification.status.title())}</p>
      </div>
    </div>

    <!-- Email Metadata Section -->
    <div class="card">
      <h3 class="section-title">Email Metadata</h3>
      <table class="meta-table">
        <tr>
          <th>From:</th>
          <td><strong>{esc(report.email_metadata.from_address)}</strong></td>
        </tr>
        <tr>
          <th>To:</th>
          <td>{esc(", ".join(report.email_metadata.to_addresses) if report.email_metadata.to_addresses else 'Undisclosed recipients')}</td>
        </tr>
        {f'<tr><th>Reply-To:</th><td>{esc(report.email_metadata.reply_to)}</td></tr>' if report.email_metadata.reply_to else ''}
        <tr>
          <th>Subject:</th>
          <td><strong>{esc(report.email_metadata.subject)}</strong></td>
        </tr>
        <tr>
          <th>Received At:</th>
          <td>{dt_str(report.email_metadata.received_at)}</td>
        </tr>
        <tr>
          <th>Message-ID:</th>
          <td><code>{esc(report.email_metadata.message_id)}</code></td>
        </tr>
        <tr>
          <th>Authentication:</th>
          <td>
            <span class="badge" style="background:#f1f5f9; color:#334155; border-color:#cbd5e1;">SPF: {esc(report.email_metadata.spf_status or 'N/A')}</span>
            <span class="badge" style="background:#f1f5f9; color:#334155; border-color:#cbd5e1;">DKIM: {esc(report.email_metadata.dkim_status or 'N/A')}</span>
            <span class="badge" style="background:#f1f5f9; color:#334155; border-color:#cbd5e1;">DMARC: {esc(report.email_metadata.dmarc_status or 'N/A')}</span>
          </td>
        </tr>
        <tr>
          <th>Artifacts:</th>
          <td>{report.email_metadata.attachment_count} attachment(s) &bull; {report.email_metadata.url_count} extracted URL(s)</td>
        </tr>
      </table>
    </div>

    <!-- Forensic Evidence Findings -->
    <div class="card">
      <h3 class="section-title">Forensic Evidence & Threat Findings ({len(report.evidence)})</h3>
      {evidence_html}
    </div>

    <!-- ML Classification -->
    <h3 class="section-title">Machine Learning Classification</h3>
    {ml_html}

    <!-- Groq Semantic Analysis -->
    <h3 class="section-title">Semantic & Intent Analysis</h3>
    {groq_html}

    <!-- External Threat Intelligence -->
    <div class="card">
      <h3 class="section-title">External Threat Intelligence Feeds</h3>
      <table class="data-table">
        <thead>
          <tr>
            <th>Indicator</th>
            <th>Type</th>
            <th>Provider</th>
            <th>Reputation</th>
            <th>Score</th>
            <th>Tags</th>
            <th>Queried</th>
          </tr>
        </thead>
        <tbody>
          {ti_html}
        </tbody>
      </table>
    </div>

    <!-- Footer Audit Trail -->
    <div class="footer-audit">
      <div>
        <strong>Generated By:</strong> {esc(report.generated_by)} &bull; <strong>Time:</strong> {dt_str(report.timestamps.report_generated_at)}
      </div>
      <div>
        <strong>Analysis ID:</strong> <code>{esc(report.analysis_id)}</code>
      </div>
    </div>
  </div>
</body>
</html>
"""
