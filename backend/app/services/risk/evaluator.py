"""Decision evaluation, taxonomy resolution, and explainability synthesis.

Responsibilities:
1. Map composite risk score to categorical severity, risk tier, and automated verdict.
2. Resolve multi-engine threat classification (ThreatCategory) via evidence weighting.
3. Determine specific attack methodology (AttackType).
4. Synthesize itemized explainable evidence (ThreatEvidenceItem).
5. Generate human-auditable SOC narrative rationale explaining every decision.
"""

from __future__ import annotations

from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import (
    AnalysisVerdict,
    AttackType,
    ReputationVerdict,
    RiskLevel,
    ThreatCategory,
    ThreatSeverity,
)
from app.services.llm.schemas import LLMIntentClassification, LLMResult
from app.services.ml.inference import MLInferenceResult
from app.services.risk.policies import RiskPolicy
from app.services.risk.schemas import (
    EngineSource,
    RiskSubscores,
    ThreatEvidenceItem,
    ThreatIntelSignal,
)


def resolve_severity(risk_score: float, policy: RiskPolicy) -> ThreatSeverity:
    """Map composite risk score to ThreatSeverity tier."""
    if risk_score >= policy.critical_threshold:
        return ThreatSeverity.CRITICAL
    if risk_score >= policy.high_threshold:
        return ThreatSeverity.HIGH
    if risk_score >= policy.medium_threshold:
        return ThreatSeverity.MEDIUM
    if risk_score >= policy.low_threshold:
        return ThreatSeverity.LOW
    return ThreatSeverity.INFO


def resolve_risk_level(risk_score: float, policy: RiskPolicy) -> RiskLevel:
    """Map composite risk score to RiskLevel tier."""
    if risk_score >= policy.critical_threshold:
        return RiskLevel.CRITICAL
    if risk_score >= policy.high_threshold:
        return RiskLevel.HIGH
    if risk_score >= policy.medium_threshold:
        return RiskLevel.MEDIUM
    if risk_score >= policy.low_threshold:
        return RiskLevel.LOW
    return RiskLevel.SAFE


def resolve_verdict(
    severity: ThreatSeverity, risk_score: float, policy: RiskPolicy
) -> AnalysisVerdict:
    """Determine automated security enforcement action."""
    if severity == ThreatSeverity.CRITICAL:
        return AnalysisVerdict.BLOCK
    if severity == ThreatSeverity.HIGH:
        return AnalysisVerdict.QUARANTINE
    if severity == ThreatSeverity.MEDIUM:
        return AnalysisVerdict.SUSPICIOUS
    return AnalysisVerdict.CLEAN


def resolve_recommendation(severity: ThreatSeverity, policy: RiskPolicy) -> str:
    """Resolve actionable recommendation matching policy configuration."""
    if severity == ThreatSeverity.CRITICAL:
        return policy.critical_action
    if severity == ThreatSeverity.HIGH:
        return policy.high_action
    if severity == ThreatSeverity.MEDIUM:
        return policy.medium_action
    if severity == ThreatSeverity.LOW:
        return policy.low_action
    return policy.safe_action


def resolve_classification(
    signals: list[NormalizedThreatSignal] | None,
    ml_result: MLInferenceResult | None,
    llm_result: LLMResult | None,
    ti_items: list[ThreatIntelSignal | NormalizedThreatSignal] | None,
    severity: ThreatSeverity,
) -> ThreatCategory:
    """Resolve primary threat classification through weighted multi-engine consensus.

    Priority order for high-severity findings:
    1. Ransomware / Malware indicators (weaponized payload is highest threat)
    2. Credential harvesting / theft
    3. Business Email Compromise (BEC) / executive fraud
    4. Brand impersonation / phishing
    5. Spam
    """
    # Check if any engine reported threat indicators
    has_active_threat = bool(signals)
    if ml_result and ml_result.classification in ("phishing", "spam"):
        has_active_threat = True
    if (
        llm_result
        and llm_result.analysis
        and (
            llm_result.analysis.is_phishing_intent
            or llm_result.analysis.is_bec_intent
            or llm_result.analysis.classification != LLMIntentClassification.BENIGN
        )
    ):
        has_active_threat = True
    if ti_items and any(
        isinstance(t, ThreatIntelSignal)
        and t.verdict in (ReputationVerdict.MALICIOUS, ReputationVerdict.SUSPICIOUS)
        for t in ti_items
    ):
        has_active_threat = True

    if not has_active_threat and severity in (ThreatSeverity.INFO, ThreatSeverity.LOW):
        return ThreatCategory.UNKNOWN

    all_signals = signals or []

    # Category weight ballot box
    category_votes: dict[ThreatCategory, float] = dict.fromkeys(ThreatCategory, 0.0)

    # 1. Deterministic signals voting
    severity_multipliers = {
        ThreatSeverity.CRITICAL: 5.0,
        ThreatSeverity.HIGH: 3.0,
        ThreatSeverity.MEDIUM: 1.5,
        ThreatSeverity.LOW: 0.5,
        ThreatSeverity.INFO: 0.1,
    }

    for sig in all_signals:
        weight = severity_multipliers.get(sig.severity, 1.0) * sig.confidence
        category_votes[sig.category] += weight

        # Direct indicators
        if "MALWARE" in sig.signal_type or "EXECUTABLE" in sig.signal_type:
            category_votes[ThreatCategory.MALWARE] += 10.0
        elif "CREDENTIAL" in sig.signal_type:
            category_votes[ThreatCategory.CREDENTIAL_THEFT] += 8.0
        elif "BEC" in sig.signal_type or "IMPERSONATION" in sig.signal_type:
            category_votes[ThreatCategory.BUSINESS_EMAIL_COMPROMISE] += 8.0

    # 2. Threat Intel voting
    if ti_items:
        for ti in ti_items:
            if isinstance(ti, ThreatIntelSignal) and ti.verdict == ReputationVerdict.MALICIOUS:
                category_votes[ThreatCategory.MALWARE] += 5.0
                category_votes[ThreatCategory.PHISHING] += 5.0
            elif isinstance(ti, NormalizedThreatSignal) and ti.severity == ThreatSeverity.CRITICAL:
                category_votes[ti.category] += 5.0

    # 3. LLM semantic classification voting
    if llm_result and llm_result.status == "success" and llm_result.analysis:
        analysis = llm_result.analysis
        llm_conf = analysis.confidence

        if analysis.is_bec_intent:
            category_votes[ThreatCategory.BUSINESS_EMAIL_COMPROMISE] += 6.0 * llm_conf
        if analysis.is_credential_request:
            category_votes[ThreatCategory.CREDENTIAL_THEFT] += 6.0 * llm_conf
        if analysis.impersonation_target:
            category_votes[ThreatCategory.BRAND_IMPERSONATION] += 4.0 * llm_conf

        mapping = {
            LLMIntentClassification.PHISHING: ThreatCategory.PHISHING,
            LLMIntentClassification.CREDENTIAL_HARVESTING: ThreatCategory.CREDENTIAL_THEFT,
            LLMIntentClassification.BUSINESS_EMAIL_COMPROMISE: ThreatCategory.BUSINESS_EMAIL_COMPROMISE,
            LLMIntentClassification.EXTORTION: ThreatCategory.SOCIAL_ENGINEERING,
            LLMIntentClassification.SOCIAL_ENGINEERING: ThreatCategory.SOCIAL_ENGINEERING,
            LLMIntentClassification.SPAM: ThreatCategory.SPAM,
        }
        mapped_cat = mapping.get(analysis.classification)
        if mapped_cat:
            category_votes[mapped_cat] += 4.0 * llm_conf

    # 4. ML voting
    if ml_result:
        if ml_result.classification == "phishing":
            category_votes[ThreatCategory.PHISHING] += 4.0 * ml_result.phishing_probability
        elif ml_result.classification == "spam":
            category_votes[ThreatCategory.SPAM] += 3.0 * ml_result.spam_probability

    # Exclude UNKNOWN from vote winner if other categories have positive votes
    active_categories = {
        k: v for k, v in category_votes.items() if k != ThreatCategory.UNKNOWN and v > 0.0
    }
    if not active_categories:
        return ThreatCategory.UNKNOWN

    winner = max(active_categories.items(), key=lambda item: item[1])[0]
    return winner


def resolve_attack_type(
    signals: list[NormalizedThreatSignal] | None,
    llm_result: LLMResult | None,
    classification: ThreatCategory,
) -> AttackType:
    """Resolve specific attack methodology (AttackType)."""
    all_signals = signals or []

    # Check for direct signals with attack_type explicitly identified
    explicit_types = [s.attack_type for s in all_signals if s.attack_type != AttackType.UNKNOWN]
    if explicit_types:
        # Return most severe attack type
        return explicit_types[0]

    # Check LLM indicators
    if llm_result and llm_result.status == "success" and llm_result.analysis:
        analysis = llm_result.analysis
        if analysis.is_bec_intent:
            return (
                AttackType.WHALING
                if "executive" in analysis.threat_narrative.lower()
                else AttackType.SPEAR_PHISHING
            )
        if analysis.is_credential_request:
            return AttackType.CREDENTIAL_HARVESTING
        if analysis.classification == LLMIntentClassification.EXTORTION:
            return AttackType.EXTORTION

    # Fallback mappings from classification
    mapping = {
        ThreatCategory.MALWARE: AttackType.MALICIOUS_DOCUMENT,
        ThreatCategory.RANSOMWARE: AttackType.RANSOMWARE_DELIVERY,
        ThreatCategory.CREDENTIAL_THEFT: AttackType.CREDENTIAL_HARVESTING,
        ThreatCategory.BUSINESS_EMAIL_COMPROMISE: AttackType.SPEAR_PHISHING,
        ThreatCategory.BRAND_IMPERSONATION: AttackType.CLONE_PHISHING,
        ThreatCategory.PHISHING: AttackType.SPEAR_PHISHING,
    }
    return mapping.get(classification, AttackType.UNKNOWN)


def build_evidence_items(
    signals: list[NormalizedThreatSignal] | None,
    ml_result: MLInferenceResult | None,
    llm_result: LLMResult | None,
    ti_items: list[ThreatIntelSignal | NormalizedThreatSignal] | None,
    subscores: RiskSubscores,
) -> list[ThreatEvidenceItem]:
    """Compile an explainable itemized list of all contributing findings."""
    evidence_items: list[ThreatEvidenceItem] = []

    # 1. Deterministic signals
    if signals:
        for sig in signals:
            source = (
                EngineSource.BEHAVIORAL_ANALYSIS
                if sig.source == "behavior_analyzer"
                else EngineSource.SECURITY_ENGINE
            )
            evidence_items.append(
                ThreatEvidenceItem(
                    source=source,
                    factor_name=sig.signal_type.lower(),
                    title=sig.title,
                    score_contribution=sig.score,
                    severity=sig.severity,
                    description=sig.description,
                    indicator_value=sig.indicator_value,
                    evidence_data=sig.evidence,
                )
            )

    # 2. Threat Intel items
    if ti_items:
        for item in ti_items:
            if isinstance(item, ThreatIntelSignal) and item.verdict != ReputationVerdict.CLEAN:
                sev = (
                    ThreatSeverity.CRITICAL
                    if item.verdict == ReputationVerdict.MALICIOUS
                    else ThreatSeverity.MEDIUM
                )
                evidence_items.append(
                    ThreatEvidenceItem(
                        source=EngineSource.THREAT_INTEL,
                        factor_name=f"ti_{item.indicator_type}_{item.provider.lower()}",
                        title=f"Threat Intel match from {item.provider}: {item.verdict.value.upper()}",
                        score_contribution=item.threat_score,
                        severity=sev,
                        description=f"Reputation match on {item.indicator_type} '{item.indicator_value}'. Tags: {', '.join(item.tags)}",
                        indicator_value=item.indicator_value,
                        evidence_data=item.details,
                    )
                )

    # 3. ML inference contribution
    if ml_result and ml_result.classification != "clean":
        evidence_items.append(
            ThreatEvidenceItem(
                source=EngineSource.ML_ENGINE,
                factor_name="ml_model_prediction",
                title=f"ML Classifier: {ml_result.classification.upper()} ({ml_result.probability:.1%})",
                score_contribution=subscores.ml,
                severity=ThreatSeverity.HIGH
                if ml_result.probability >= 0.8
                else ThreatSeverity.MEDIUM,
                description=f"Model version {ml_result.model_version} predicted {ml_result.classification} with {ml_result.confidence:.1%} confidence.",
                indicator_value=None,
                evidence_data={
                    "classification": ml_result.classification,
                    "probability": ml_result.probability,
                    "top_features": dict(list(ml_result.features_used.items())[:5]),
                },
            )
        )

    # 4. Groq LLM contribution
    if llm_result and llm_result.status == "success" and llm_result.analysis:
        analysis = llm_result.analysis
        if analysis.is_phishing_intent or analysis.is_bec_intent:
            evidence_items.append(
                ThreatEvidenceItem(
                    source=EngineSource.GROQ_LLM,
                    factor_name="groq_semantic_intent",
                    title=f"Groq LLM Semantic Finding: {analysis.classification.value.upper()}",
                    score_contribution=subscores.llm,
                    severity=ThreatSeverity.HIGH
                    if analysis.confidence >= 0.8
                    else ThreatSeverity.MEDIUM,
                    description=analysis.executive_summary,
                    indicator_value=analysis.impersonation_target,
                    evidence_data={
                        "tactics": analysis.social_engineering_tactics,
                        "impersonation_target": analysis.impersonation_target,
                        "evidence_quotes": analysis.evidence_quotes,
                    },
                )
            )

    return evidence_items


def generate_explainable_rationale(
    risk_score: float,
    severity: ThreatSeverity,
    classification: ThreatCategory,
    subscores: RiskSubscores,
    weights_applied: dict[str, float],
    evidence_items: list[ThreatEvidenceItem],
    hard_floor_applied: bool,
    hard_floor_reason: str | None,
) -> str:
    """Generate human-readable SOC narrative explaining why this decision was reached."""
    parts = [
        f"Assigned risk score is {risk_score:.1f}/100 ({severity.value.upper()}, category: {classification.value})."
    ]

    # Component contributions
    contributions = []
    if weights_applied.get("security", 0.0) > 0.0 and subscores.security > 0.0:
        contributions.append(
            f"Security Engine ({subscores.security:.1f}pts @ {weights_applied['security']:.0%})"
        )
    if weights_applied.get("ml", 0.0) > 0.0 and subscores.ml > 0.0:
        contributions.append(f"ML Classifier ({subscores.ml:.1f}pts @ {weights_applied['ml']:.0%})")
    if weights_applied.get("llm", 0.0) > 0.0 and subscores.llm > 0.0:
        contributions.append(f"Groq LLM ({subscores.llm:.1f}pts @ {weights_applied['llm']:.0%})")
    if weights_applied.get("threat_intel", 0.0) > 0.0 and subscores.threat_intel > 0.0:
        contributions.append(
            f"Threat Intel ({subscores.threat_intel:.1f}pts @ {weights_applied['threat_intel']:.0%})"
        )
    if weights_applied.get("behavioral", 0.0) > 0.0 and subscores.behavioral > 0.0:
        contributions.append(
            f"Behavioral Heuristics ({subscores.behavioral:.1f}pts @ {weights_applied['behavioral']:.0%})"
        )

    if contributions:
        parts.append(f"Primary risk drivers: {'; '.join(contributions)}.")
    else:
        parts.append("No elevated risk indicators observed across active detection engines.")

    # Highlighting key findings
    key_findings = [
        e.title
        for e in evidence_items
        if e.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)
    ]
    if key_findings:
        parts.append(f"Critical/High findings: {', '.join(key_findings[:3])}.")

    # Document hard floor enforcement
    if hard_floor_applied:
        parts.append(
            f"[SAFETY POLICY ENFORCED]: Hard security floor triggered. Rationale: {hard_floor_reason}."
        )

    return " ".join(parts)
