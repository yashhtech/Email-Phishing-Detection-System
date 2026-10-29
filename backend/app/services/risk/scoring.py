"""Centralized scoring logic and multi-engine fusion algorithms.

Responsibilities:
1. Normalize and aggregate subscores across all 5 analysis dimensions:
   - Security Engine (deterministic findings)
   - Behavioral Analysis (urgency, evasion, forms)
   - Machine Learning (statistical classification)
   - Groq LLM (semantic intent, social engineering)
   - Threat Intelligence (IOC reputation, blocklists)
2. Dynamically re-normalize weights when optional engines are unconfigured or unavailable.
3. Compute composite risk score (0.0 to 100.0).
4. Strictly enforce hard security invariants (floors) preventing silent overrides by LLMs.
5. Synthesize mathematically blended confidence based on inter-engine agreement.
"""

from __future__ import annotations

import structlog

from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import ReputationVerdict, ThreatSeverity
from app.services.llm.schemas import LLMIntentClassification, LLMResult
from app.services.ml.inference import MLInferenceResult
from app.services.risk.policies import RiskPolicy
from app.services.risk.schemas import RiskSubscores, ThreatIntelSignal

logger = structlog.get_logger(__name__)


# -----------------------------------------------------------------------------
# 1. Deterministic Security Subscore (Security Engine)
# -----------------------------------------------------------------------------


def calculate_security_subscore(signals: list[NormalizedThreatSignal] | None) -> float:
    """Calculate normalized subscore for deterministic security findings (0.0 - 100.0).

    Uses a non-linear saturation formula:
        S = 100 * (1 - Prod(1 - (score_i * confidence_i) / 100))
    This ensures multiple compounding indicators elevate the score naturally
    without exceeding 100.0, while a single high/critical finding contributes immediately.
    """
    if not signals:
        return 0.0

    # Filter for security engine sources
    security_sources = {
        "sender_analyzer",
        "header_analyzer",
        "authentication_analyzer",
        "url_analyzer",
        "domain_analyzer",
        "attachment_analyzer",
        "security_engine",
    }
    relevant_signals = [
        s for s in signals if s.source in security_sources or s.source.endswith("_analyzer")
    ]

    if not relevant_signals:
        return 0.0

    # Check for immediate critical floor within deterministic signals
    has_critical = any(s.severity == ThreatSeverity.CRITICAL for s in relevant_signals)
    has_high = any(s.severity == ThreatSeverity.HIGH for s in relevant_signals)

    # Accumulate independent risk probability products
    complement_product = 1.0
    for sig in relevant_signals:
        # Effective individual risk impact
        impact = (sig.score * sig.confidence) / 100.0
        # Bound each factor's individual reduction to prevent math anomalies
        factor = max(0.0, min(0.95, impact))
        complement_product *= 1.0 - factor

    calculated = 100.0 * (1.0 - complement_product)

    # Enforce internal baseline anchors
    if has_critical:
        calculated = max(calculated, 85.0)
    elif has_high:
        calculated = max(calculated, 65.0)

    return round(min(100.0, max(0.0, calculated)), 2)


# -----------------------------------------------------------------------------
# 2. Behavioral Analysis Subscore
# -----------------------------------------------------------------------------


def calculate_behavioral_subscore(signals: list[NormalizedThreatSignal] | None) -> float:
    """Calculate subscore for behavioral manipulation heuristics (0.0 - 100.0)."""
    if not signals:
        return 0.0

    behavioral_signals = [
        s
        for s in signals
        if s.source in ("behavior_analyzer", "behavioral_analysis")
        or "BEHAVIOR" in s.signal_type
        or "URGENCY" in s.signal_type
        or "EVASION" in s.signal_type
    ]
    if not behavioral_signals:
        return 0.0

    complement_product = 1.0
    for sig in behavioral_signals:
        impact = (sig.score * sig.confidence) / 100.0
        factor = max(0.0, min(0.90, impact))
        complement_product *= 1.0 - factor

    calculated = 100.0 * (1.0 - complement_product)
    return round(min(100.0, max(0.0, calculated)), 2)


# -----------------------------------------------------------------------------
# 3. Machine Learning Subscore
# -----------------------------------------------------------------------------


def calculate_ml_subscore(ml_result: MLInferenceResult | None) -> tuple[float, bool]:
    """Calculate subscore from ML inference output.

    Returns:
        Tuple of (subscore: float, is_active: bool)
    """
    if ml_result is None:
        return 0.0, False

    # Phishing probability drives the threat score directly
    phishing_contrib = ml_result.phishing_probability * 100.0
    # Spam contributes moderately to threat score
    spam_contrib = ml_result.spam_probability * 40.0

    raw_score = max(phishing_contrib, spam_contrib)

    # If classification is clean, scale down proportionally to clean probability
    if ml_result.classification == "clean":
        raw_score = min(raw_score, (1.0 - ml_result.clean_probability) * 30.0)

    # Weight score by model confidence
    weighted_score = (raw_score * 0.8) + (raw_score * ml_result.confidence * 0.2)
    return round(min(100.0, max(0.0, weighted_score)), 2), True


# -----------------------------------------------------------------------------
# 4. Groq LLM Subscore
# -----------------------------------------------------------------------------


def calculate_llm_subscore(llm_result: LLMResult | None) -> tuple[float, bool]:
    """Calculate subscore from Groq LLM semantic analysis.

    Returns:
        Tuple of (subscore: float, is_active: bool)
    """
    if llm_result is None:
        return 0.0, False

    # If unconfigured, timeout, or failed, treat as inactive for weight redistribution
    if llm_result.status != "success" or llm_result.analysis is None:
        return 0.0, False

    analysis = llm_result.analysis
    base_score = 0.0

    # Primary intent evaluation
    if analysis.is_phishing_intent:
        base_score = 75.0
    elif analysis.is_bec_intent:
        base_score = 80.0
    elif analysis.classification in (
        LLMIntentClassification.PHISHING,
        LLMIntentClassification.CREDENTIAL_HARVESTING,
        LLMIntentClassification.BUSINESS_EMAIL_COMPROMISE,
        LLMIntentClassification.EXTORTION,
    ):
        base_score = 70.0
    elif analysis.classification == LLMIntentClassification.SOCIAL_ENGINEERING:
        base_score = 55.0
    elif analysis.classification == LLMIntentClassification.SPAM:
        base_score = 30.0
    elif analysis.classification == LLMIntentClassification.BENIGN:
        base_score = 5.0
    else:
        base_score = 15.0

    # Specific threat capability escalations
    if analysis.is_credential_request:
        base_score += 15.0
    if analysis.is_payment_request:
        base_score += 15.0
    if analysis.impersonation_target:
        base_score += 10.0

    # Bonus for identified psychological coercion tactics
    tactic_bonus = min(15.0, len(analysis.social_engineering_tactics) * 5.0)
    base_score += tactic_bonus

    # Scale with LLM self-reported confidence
    confidence_factor = max(0.5, analysis.confidence)
    final_subscore = base_score * confidence_factor

    # If benign, cap strictly
    if (
        analysis.classification == LLMIntentClassification.BENIGN
        and not analysis.is_phishing_intent
    ):
        final_subscore = min(final_subscore, 15.0)

    return round(min(100.0, max(0.0, final_subscore)), 2), True


# -----------------------------------------------------------------------------
# 5. Threat Intelligence Subscore
# -----------------------------------------------------------------------------


def calculate_threat_intel_subscore(
    ti_items: list[ThreatIntelSignal | NormalizedThreatSignal] | None,
) -> tuple[float, bool]:
    """Calculate subscore from threat intelligence reputation and IOC matches.

    Returns:
        Tuple of (subscore: float, is_active: bool)
    """
    if not ti_items:
        return 0.0, False

    highest_score = 0.0
    has_malicious = False

    for item in ti_items:
        if isinstance(item, ThreatIntelSignal):
            if item.verdict == ReputationVerdict.MALICIOUS:
                has_malicious = True
                score = max(item.threat_score, 85.0) * item.confidence
            elif item.verdict == ReputationVerdict.SUSPICIOUS:
                score = max(item.threat_score, 50.0) * item.confidence
            elif item.verdict == ReputationVerdict.CLEAN:
                score = 0.0
            else:
                score = item.threat_score * item.confidence
            highest_score = max(highest_score, score)

        elif isinstance(item, NormalizedThreatSignal):
            if item.source == "threat_intel":
                if item.severity == ThreatSeverity.CRITICAL:
                    has_malicious = True
                    highest_score = max(highest_score, 95.0)
                elif item.severity == ThreatSeverity.HIGH:
                    highest_score = max(highest_score, 75.0)
                elif item.severity == ThreatSeverity.MEDIUM:
                    highest_score = max(highest_score, 50.0)
                else:
                    highest_score = max(highest_score, item.score * item.confidence)

    if has_malicious:
        highest_score = max(highest_score, 85.0)

    return round(min(100.0, max(0.0, highest_score)), 2), True


# -----------------------------------------------------------------------------
# 6. Dynamic Weight Re-normalization
# -----------------------------------------------------------------------------


def compute_effective_weights(
    policy: RiskPolicy,
    active_components: dict[str, bool],
) -> dict[str, float]:
    """Dynamically re-normalize weights across active components.

    If optional components (like Threat Intel feeds or Groq LLM) are unavailable,
    their weights are distributed proportionally across remaining active engines.
    """
    raw_weights = {
        "security": policy.security_weight,
        "behavioral": policy.behavioral_weight,
        "ml": policy.ml_weight,
        "llm": policy.llm_weight,
        "threat_intel": policy.threat_intel_weight,
    }

    # Sum weights of active components
    active_sum = sum(
        weight for comp, weight in raw_weights.items() if active_components.get(comp, False)
    )

    if active_sum <= 0.0:
        # Fallback if no components are active
        return {"security": 1.0, "behavioral": 0.0, "ml": 0.0, "llm": 0.0, "threat_intel": 0.0}

    # Normalize active weights to sum exactly to 1.0
    effective = {}
    for comp, weight in raw_weights.items():
        if active_components.get(comp, False):
            effective[comp] = round(weight / active_sum, 4)
        else:
            effective[comp] = 0.0

    return effective


# -----------------------------------------------------------------------------
# 7. Composite Risk Fusion and Hard Security Floor Enforcement
# -----------------------------------------------------------------------------


def compute_composite_risk(
    subscores: RiskSubscores,
    effective_weights: dict[str, float],
    signals: list[NormalizedThreatSignal] | None,
    ti_items: list[ThreatIntelSignal | NormalizedThreatSignal] | None,
    llm_result: LLMResult | None,
    policy: RiskPolicy,
) -> tuple[float, bool, str | None]:
    """Compute the final composite risk score and apply hard security invariants.

    Returns:
        Tuple of (final_risk_score, hard_floor_applied, hard_floor_reason)
    """
    # 1. Base weighted linear combination
    raw_composite = (
        subscores.security * effective_weights.get("security", 0.0)
        + subscores.behavioral * effective_weights.get("behavioral", 0.0)
        + subscores.ml * effective_weights.get("ml", 0.0)
        + subscores.llm * effective_weights.get("llm", 0.0)
        + subscores.threat_intel * effective_weights.get("threat_intel", 0.0)
    )

    composite = min(100.0, max(0.0, raw_composite))
    floor_applied = False
    floor_reason: str | None = None

    # 2. Check for CRITICAL hard security signals
    all_signals = signals or []
    critical_signals = [s for s in all_signals if s.severity == ThreatSeverity.CRITICAL]

    ti_critical = False
    if ti_items:
        for t in ti_items:
            if (
                isinstance(t, ThreatIntelSignal)
                and t.verdict == ReputationVerdict.MALICIOUS
                and t.confidence >= 0.7
            ):
                ti_critical = True
                break
            elif isinstance(t, NormalizedThreatSignal) and t.severity == ThreatSeverity.CRITICAL:
                ti_critical = True
                break

    # Check if LLM returned contradictory "benign" assessment
    llm_contradicts = False
    if llm_result and llm_result.status == "success" and llm_result.analysis:
        if (
            llm_result.analysis.classification == LLMIntentClassification.BENIGN
            and not llm_result.analysis.is_phishing_intent
        ):
            llm_contradicts = True

    # 3. Apply CRITICAL Hard Security Floor
    if policy.enforce_critical_hard_floor and (critical_signals or ti_critical):
        if composite < policy.critical_floor_score:
            floor_applied = True
            reasons = []
            if critical_signals:
                reasons.append(
                    f"Critical hard signal(s): {', '.join(s.title for s in critical_signals[:2])}"
                )
            if ti_critical:
                reasons.append("Confirmed malicious threat intelligence match")
            if llm_contradicts and policy.prohibit_llm_override:
                reasons.append("Contradictory benign LLM assessment safely overridden")

            floor_reason = " | ".join(reasons)
            logger.warning(
                "hard_security_critical_floor_enforced",
                raw_score=composite,
                floor_score=policy.critical_floor_score,
                reason=floor_reason,
            )
            composite = policy.critical_floor_score

    # 4. Apply HIGH Hard Security Floor (Severe authentication or spoofing failure)
    elif policy.enforce_high_hard_floor:
        high_auth_or_spoofing = [
            s
            for s in all_signals
            if s.severity == ThreatSeverity.HIGH
            and s.signal_type
            in (
                "SPF_FAIL",
                "DKIM_FAIL",
                "DMARC_REJECT",
                "SPOOFED_DISPLAY_NAME",
                "BRAND_IMPERSONATION",
                "EXECUTABLE_ATTACHMENT",
                "IP_BASED_URL",
                "PUNYCODE_HOMOGRAPH",
            )
        ]
        if high_auth_or_spoofing and composite < policy.high_floor_score:
            floor_applied = True
            reasons = [f"High-severity security signal: {high_auth_or_spoofing[0].title}"]
            if llm_contradicts and policy.prohibit_llm_override:
                reasons.append("Contradictory benign LLM assessment safely overridden")

            floor_reason = " | ".join(reasons)
            logger.info(
                "hard_security_high_floor_enforced",
                raw_score=composite,
                floor_score=policy.high_floor_score,
                reason=floor_reason,
            )
            composite = policy.high_floor_score

    return round(composite, 2), floor_applied, floor_reason


# -----------------------------------------------------------------------------
# 8. Aggregated Confidence Calculation
# -----------------------------------------------------------------------------


def compute_blended_confidence(
    active_components: dict[str, bool],
    signals: list[NormalizedThreatSignal] | None,
    ml_result: MLInferenceResult | None,
    llm_result: LLMResult | None,
    ti_items: list[ThreatIntelSignal | NormalizedThreatSignal] | None,
) -> float:
    """Compute mathematical confidence in the overall assessment.

    Blends individual component confidences with a consensus agreement multiplier.
    """
    confidences: list[float] = []

    # Security engine confidence (highest confidence of present signals, or default 0.85)
    if signals:
        confidences.append(max(s.confidence for s in signals))
    elif active_components.get("security", False):
        confidences.append(0.80)

    # ML confidence
    if ml_result and active_components.get("ml", False):
        confidences.append(ml_result.confidence)

    # LLM confidence
    if llm_result and llm_result.analysis and active_components.get("llm", False):
        confidences.append(llm_result.analysis.confidence)

    # Threat Intel confidence
    if ti_items and active_components.get("threat_intel", False):
        ti_conf = [
            t.confidence
            for t in ti_items
            if isinstance(t, (ThreatIntelSignal, NormalizedThreatSignal))
        ]
        if ti_conf:
            confidences.append(max(ti_conf))

    if not confidences:
        return 0.50

    # Mean of individual confidences
    base_confidence = sum(confidences) / len(confidences)

    # Multi-engine consensus bonus: if 3 or more engines agree on the threat
    if len(confidences) >= 3:
        base_confidence = min(1.0, base_confidence * 1.05)

    return round(min(1.0, max(0.1, base_confidence)), 2)
