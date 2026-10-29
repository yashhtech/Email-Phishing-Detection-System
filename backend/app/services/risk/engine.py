"""RiskEngine — central coordinator for holistic email risk scoring and policy enforcement.

Coordinates multi-engine signal fusion across:
- Security Engine (deterministic findings)
- Behavioral Analysis (urgency lures, zero-font evasion, deceptive links)
- Machine Learning Engine (statistical features)
- Groq LLM Provider (semantic intent, social engineering)
- Threat Intelligence (IOC reputation, blocklists)

Operational Invariants:
1. No single component directly dictates the final outcome (balanced fusion).
2. Hard security floors prevent silent downgrade of high/critical threats by LLMs.
3. Every decision produces itemized, explainable evidence.
4. Scoring weights and thresholds are strictly policy-driven and configurable.
"""

from __future__ import annotations

import structlog

from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.services.llm.schemas import LLMResult
from app.services.ml.inference import MLInferenceResult
from app.services.risk.evaluator import (
    build_evidence_items,
    generate_explainable_rationale,
    resolve_attack_type,
    resolve_classification,
    resolve_recommendation,
    resolve_risk_level,
    resolve_severity,
    resolve_verdict,
)
from app.services.risk.policies import DEFAULT_ENTERPRISE_POLICY, RiskPolicy
from app.services.risk.schemas import (
    RiskAssessment,
    RiskSubscores,
    ThreatIntelSignal,
)
from app.services.risk.scoring import (
    calculate_behavioral_subscore,
    calculate_llm_subscore,
    calculate_ml_subscore,
    calculate_security_subscore,
    calculate_threat_intel_subscore,
    compute_blended_confidence,
    compute_composite_risk,
    compute_effective_weights,
)

logger = structlog.get_logger(__name__)


class RiskEngine:
    """Authoritative enterprise risk engine for email threat detection."""

    ENGINE_VERSION = "2026.1.0"

    def __init__(self, default_policy: RiskPolicy | None = None) -> None:
        self.default_policy = default_policy or DEFAULT_ENTERPRISE_POLICY

    def assess(
        self,
        security_signals: list[NormalizedThreatSignal] | None = None,
        behavioral_signals: list[NormalizedThreatSignal] | None = None,
        ml_result: MLInferenceResult | None = None,
        llm_result: LLMResult | None = None,
        threat_intel_signals: list[ThreatIntelSignal | NormalizedThreatSignal] | None = None,
        policy: RiskPolicy | None = None,
    ) -> RiskAssessment:
        """Execute risk evaluation across all available signal dimensions.

        Args:
            security_signals: Findings from deterministic security analyzers
                (sender, header, auth, url, domain, attachment).
            behavioral_signals: Findings from behavioral analysis
                (urgency lures, hidden zero-font HTML, deceptive link mismatches).
            ml_result: Prediction and probabilities from ML classification service.
            llm_result: Semantic intent analysis from Groq LLM provider.
            threat_intel_signals: External/internal reputation findings and IOC matches.
            policy: Configurable risk policy overriding default enterprise policy.

        Returns:
            Authoritative, fully explainable RiskAssessment instance.
        """
        active_policy = policy or self.default_policy
        sec_signals = security_signals or []
        beh_signals = behavioral_signals or []
        all_signals = sec_signals + beh_signals

        # ---------------------------------------------------------------------
        # 1. Calculate Component Subscores and Determine Active Engines
        # ---------------------------------------------------------------------
        sec_subscore = calculate_security_subscore(sec_signals)
        beh_subscore = calculate_behavioral_subscore(beh_signals)
        ml_subscore, ml_active = calculate_ml_subscore(ml_result)
        llm_subscore, llm_active = calculate_llm_subscore(llm_result)
        ti_subscore, ti_active = calculate_threat_intel_subscore(threat_intel_signals)

        subscores = RiskSubscores(
            security=sec_subscore,
            behavioral=beh_subscore,
            ml=ml_subscore,
            llm=llm_subscore,
            threat_intel=ti_subscore,
        )

        active_components = {
            "security": True,  # Deterministic checks always run
            "behavioral": True,  # Behavioral checks always run
            "ml": ml_active,
            "llm": llm_active,
            "threat_intel": ti_active,
        }

        # ---------------------------------------------------------------------
        # 2. Dynamic Weight Re-normalization
        # ---------------------------------------------------------------------
        weights_applied = compute_effective_weights(active_policy, active_components)

        # ---------------------------------------------------------------------
        # 3. Composite Risk Fusion and Hard Security Floor Enforcement
        # ---------------------------------------------------------------------
        risk_score, hard_floor_applied, hard_floor_reason = compute_composite_risk(
            subscores=subscores,
            effective_weights=weights_applied,
            signals=all_signals,
            ti_items=threat_intel_signals,
            llm_result=llm_result,
            policy=active_policy,
        )

        # ---------------------------------------------------------------------
        # 4. Evaluation and Mapping
        # ---------------------------------------------------------------------
        severity = resolve_severity(risk_score, active_policy)
        risk_level = resolve_risk_level(risk_score, active_policy)
        verdict = resolve_verdict(severity, risk_score, active_policy)
        recommendation = resolve_recommendation(severity, active_policy)

        classification = resolve_classification(
            signals=all_signals,
            ml_result=ml_result,
            llm_result=llm_result,
            ti_items=threat_intel_signals,
            severity=severity,
        )

        attack_type = resolve_attack_type(
            signals=all_signals,
            llm_result=llm_result,
            classification=classification,
        )

        confidence = compute_blended_confidence(
            active_components=active_components,
            signals=all_signals,
            ml_result=ml_result,
            llm_result=llm_result,
            ti_items=threat_intel_signals,
        )

        # ---------------------------------------------------------------------
        # 5. Synthesize Itemized Evidence and SOC Audit Rationale
        # ---------------------------------------------------------------------
        evidence = build_evidence_items(
            signals=all_signals,
            ml_result=ml_result,
            llm_result=llm_result,
            ti_items=threat_intel_signals,
            subscores=subscores,
        )

        rationale = generate_explainable_rationale(
            risk_score=risk_score,
            severity=severity,
            classification=classification,
            subscores=subscores,
            weights_applied=weights_applied,
            evidence_items=evidence,
            hard_floor_applied=hard_floor_applied,
            hard_floor_reason=hard_floor_reason,
        )

        logger.info(
            "risk_assessment_completed",
            risk_score=risk_score,
            severity=severity.value,
            verdict=verdict.value,
            classification=classification.value,
            hard_floor_applied=hard_floor_applied,
            policy=active_policy.name,
        )

        return RiskAssessment(
            risk_score=risk_score,
            severity=severity,
            risk_level=risk_level,
            verdict=verdict,
            confidence=confidence,
            classification=classification,
            attack_type=attack_type,
            signals=all_signals,
            evidence=evidence,
            recommendation=recommendation,
            engine_version=self.ENGINE_VERSION,
            subscores=subscores,
            weights_applied=weights_applied,
            policy_name=active_policy.name,
            hard_floor_applied=hard_floor_applied,
            hard_floor_reason=hard_floor_reason,
            rationale=rationale,
        )
