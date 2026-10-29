"""Extensive unit tests for the Risk Engine service.

Coverage:
1. Centralized Subscore Calculations:
   - Security subscore (diminishing returns, critical floors, single/multiple signals)
   - Behavioral subscore (urgency, evasion, anchor text mismatches)
   - ML subscore (phishing probability, spam, clean scaling, confidence weighting)
   - Groq LLM subscore (phishing intent, BEC, credential/payment requests, tactics bonus, benign capping)
   - Threat Intelligence subscore (malicious IOCs, suspicious reputation, clean)
2. Dynamic Weight Re-normalization:
   - All engines active (weights sum to 1.0)
   - Unconfigured/failed LLM gracefully redistributes weight
   - Missing threat intel gracefully redistributes weight
   - Graceful fallback when only deterministic engine is active
3. Hard Security Invariants (Floors preventing LLM overrides):
   - Critical hard floor enforced when malware attachment present despite benign LLM
   - Critical hard floor enforced on malicious Threat Intel IOC match despite benign LLM
   - High hard floor enforced on severe SPF/DKIM/DMARC failure despite benign LLM
   - Policy option to disable hard floors respected
   - Hard floor telemetry recorded in RiskAssessment
4. Configurable Risk Policies:
   - Default Enterprise Policy thresholds and behavior
   - Zero-Trust Aggressive Policy (lower quarantine threshold: 55.0)
   - Permissive Policy (higher quarantine threshold: 75.0)
   - Custom weights and thresholds validation
   - Policy threshold documentation audit
5. Threat Taxonomy and Classification Resolution:
   - Malware / Ransomware classification priority
   - Business Email Compromise (BEC) resolution
   - Credential theft resolution
   - Specific attack type mapping (Whaling, Malicious Document, Credential Harvesting)
6. Complete RiskAssessment Contract & Explainability:
   - All required fields present, strictly typed, and valid
   - Itemized ThreatEvidenceItem compilation
   - Human-auditable SOC narrative rationale
   - Inter-engine consensus confidence blending
"""

from __future__ import annotations

from typing import Any

import pytest

from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import (
    AnalysisVerdict,
    AttackType,
    ReputationVerdict,
    RiskLevel,
    ThreatCategory,
    ThreatSeverity,
)
from app.services.llm.schemas import (
    LLMAnalysisResponse,
    LLMIntentClassification,
    LLMResult,
)
from app.services.ml.inference import MLInferenceResult
from app.services.risk.engine import RiskEngine
from app.services.risk.policies import (
    DEFAULT_ENTERPRISE_POLICY,
    PERMISSIVE_POLICY,
    ZERO_TRUST_AGGRESSIVE_POLICY,
    RiskPolicy,
)
from app.services.risk.schemas import (
    EngineSource,
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
    compute_effective_weights,
)

# ---------------------------------------------------------------------------
# Test Helpers & Fixtures
# ---------------------------------------------------------------------------


def _make_signal(
    source: str = "sender_analyzer",
    signal_type: str = "SPOOFED_DISPLAY_NAME",
    category: ThreatCategory = ThreatCategory.PHISHING,
    severity: ThreatSeverity = ThreatSeverity.HIGH,
    attack_type: AttackType = AttackType.SPOOFING,
    score: float = 75.0,
    confidence: float = 0.90,
    title: str = "Spoofed Display Name",
    description: str = "Sender display name impersonates an executive.",
    evidence: dict[str, Any] | None = None,
    indicator_value: str | None = None,
) -> NormalizedThreatSignal:
    return NormalizedThreatSignal(
        source=source,
        signal_type=signal_type,
        category=category,
        severity=severity,
        attack_type=attack_type,
        score=score,
        confidence=confidence,
        title=title,
        description=description,
        evidence=evidence or {},
        indicator_value=indicator_value,
    )


def _make_ml_result(
    classification: str = "phishing",
    phishing_probability: float = 0.92,
    spam_probability: float = 0.05,
    clean_probability: float = 0.03,
    confidence: float = 0.90,
) -> MLInferenceResult:
    return MLInferenceResult(
        classification=classification,
        probability=phishing_probability if classification == "phishing" else clean_probability,
        phishing_probability=phishing_probability,
        spam_probability=spam_probability,
        clean_probability=clean_probability,
        confidence=confidence,
        model_version="v1.0.0",
        features_used={"url_count": 2.0, "has_ip_url": 1.0, "auth_fail_count": 2.0},
        feature_contributions={"has_ip_url": 0.45, "auth_fail_count": 0.35},
        inference_latency_ms=1.2,
    )


def _make_llm_result(
    classification: LLMIntentClassification = LLMIntentClassification.PHISHING,
    confidence: float = 0.90,
    is_phishing_intent: bool = True,
    is_bec_intent: bool = False,
    is_credential_request: bool = True,
    is_payment_request: bool = False,
    tactics: list[str] | None = None,
    impersonation_target: str | None = "Microsoft",
    status: str = "success",
) -> LLMResult:
    analysis = LLMAnalysisResponse(
        classification=classification,
        confidence=confidence,
        is_phishing_intent=is_phishing_intent,
        is_bec_intent=is_bec_intent,
        is_credential_request=is_credential_request,
        is_payment_request=is_payment_request,
        social_engineering_tactics=tactics or ["urgency", "authority_impersonation"],
        impersonation_target=impersonation_target,
        threat_narrative="Email impersonates Microsoft and solicits immediate credential re-authentication.",
        executive_summary="High-risk credential harvesting attempt mimicking Microsoft 365.",
        recommended_action="quarantine",
        evidence_quotes=["Verify your password immediately"],
    )
    return LLMResult(
        provider="groq",
        model="llama3-8b-8192",
        status=status,
        confidence=confidence,
        classification=classification.value,
        latency_ms=150.0,
        analysis=analysis if status == "success" else None,
    )


def _make_ti_signal(
    indicator_value: str = "malicious-phish.com",
    verdict: ReputationVerdict = ReputationVerdict.MALICIOUS,
    threat_score: float = 95.0,
    confidence: float = 0.95,
) -> ThreatIntelSignal:
    return ThreatIntelSignal(
        indicator_type="domain",
        indicator_value=indicator_value,
        provider="VirusTotal",
        verdict=verdict,
        threat_score=threat_score,
        confidence=confidence,
        tags=["phishing", "credential_theft"],
        details={"positives": 14, "total": 70},
    )


# ===========================================================================
# 1. Centralized Subscore Calculations Tests
# ===========================================================================


class TestScoringSubscores:
    """Unit tests for individual subscore calculation algorithms."""

    def test_security_subscore_empty_returns_zero(self) -> None:
        assert calculate_security_subscore([]) == 0.0
        assert calculate_security_subscore(None) == 0.0

    def test_security_subscore_single_medium_signal(self) -> None:
        signal = _make_signal(
            source="sender_analyzer",
            severity=ThreatSeverity.MEDIUM,
            score=50.0,
            confidence=0.8,
        )
        subscore = calculate_security_subscore([signal])
        assert 35.0 <= subscore <= 50.0

    def test_security_subscore_compounding_multiple_signals(self) -> None:
        sig1 = _make_signal(
            source="header_analyzer", score=40.0, confidence=0.8, severity=ThreatSeverity.MEDIUM
        )
        sig2 = _make_signal(
            source="url_analyzer", score=50.0, confidence=0.8, severity=ThreatSeverity.MEDIUM
        )
        sig3 = _make_signal(
            source="domain_analyzer", score=45.0, confidence=0.8, severity=ThreatSeverity.MEDIUM
        )

        score_single = calculate_security_subscore([sig1])
        score_combined = calculate_security_subscore([sig1, sig2, sig3])

        # Compounding signals must elevate the score higher than any single signal
        assert score_combined > score_single
        assert score_combined <= 100.0

    def test_security_subscore_critical_signal_enforces_floor(self) -> None:
        critical_signal = _make_signal(
            source="attachment_analyzer",
            signal_type="EXECUTABLE_ATTACHMENT",
            severity=ThreatSeverity.CRITICAL,
            score=90.0,
            confidence=0.95,
        )
        subscore = calculate_security_subscore([critical_signal])
        assert subscore >= 85.0

    def test_behavioral_subscore_urgency_heuristics(self) -> None:
        sig = _make_signal(
            source="behavior_analyzer",
            signal_type="URGENCY_COERCION_LURE",
            severity=ThreatSeverity.MEDIUM,
            score=55.0,
            confidence=0.85,
        )
        subscore = calculate_behavioral_subscore([sig])
        assert subscore > 0.0
        assert subscore <= 100.0

    def test_behavioral_subscore_empty_returns_zero(self) -> None:
        assert calculate_behavioral_subscore([]) == 0.0
        assert calculate_behavioral_subscore(None) == 0.0

    def test_ml_subscore_none_inactive(self) -> None:
        subscore, active = calculate_ml_subscore(None)
        assert subscore == 0.0
        assert active is False

    def test_ml_subscore_phishing_high(self) -> None:
        ml = _make_ml_result(classification="phishing", phishing_probability=0.95, confidence=0.92)
        subscore, active = calculate_ml_subscore(ml)
        assert active is True
        assert subscore >= 85.0

    def test_ml_subscore_clean_scales_down(self) -> None:
        ml = _make_ml_result(
            classification="clean",
            phishing_probability=0.02,
            clean_probability=0.98,
            confidence=0.95,
        )
        subscore, active = calculate_ml_subscore(ml)
        assert active is True
        assert subscore <= 10.0

    def test_llm_subscore_none_or_failed_inactive(self) -> None:
        subscore, active = calculate_llm_subscore(None)
        assert subscore == 0.0
        assert active is False

        failed_llm = LLMResult(
            provider="groq",
            model="llama3-8b-8192",
            status="api_error",
            confidence=0.0,
            classification="unknown",
            latency_ms=10.0,
            error_message="HTTP 500",
        )
        subscore, active = calculate_llm_subscore(failed_llm)
        assert subscore == 0.0
        assert active is False

    def test_llm_subscore_phishing_and_credentials(self) -> None:
        llm = _make_llm_result(
            classification=LLMIntentClassification.CREDENTIAL_HARVESTING,
            confidence=0.95,
            is_credential_request=True,
            tactics=["urgency", "authority", "fear"],
        )
        subscore, active = calculate_llm_subscore(llm)
        assert active is True
        assert subscore >= 80.0

    def test_llm_subscore_benign_strictly_capped(self) -> None:
        llm = _make_llm_result(
            classification=LLMIntentClassification.BENIGN,
            confidence=0.95,
            is_phishing_intent=False,
            is_credential_request=False,
            tactics=[],
            impersonation_target=None,
        )
        subscore, active = calculate_llm_subscore(llm)
        assert active is True
        assert subscore <= 15.0

    def test_threat_intel_subscore_none_inactive(self) -> None:
        subscore, active = calculate_threat_intel_subscore(None)
        assert subscore == 0.0
        assert active is False

    def test_threat_intel_subscore_malicious_ioc(self) -> None:
        ti = _make_ti_signal(
            verdict=ReputationVerdict.MALICIOUS, threat_score=95.0, confidence=0.95
        )
        subscore, active = calculate_threat_intel_subscore([ti])
        assert active is True
        assert subscore >= 85.0

    def test_threat_intel_subscore_clean_zero(self) -> None:
        ti = _make_ti_signal(verdict=ReputationVerdict.CLEAN, threat_score=0.0, confidence=0.90)
        subscore, active = calculate_threat_intel_subscore([ti])
        assert active is True
        assert subscore == 0.0


# ===========================================================================
# 2. Dynamic Weight Re-normalization Tests
# ===========================================================================


class TestDynamicWeightRenormalization:
    """Validate that inactive engines redistribute weight proportionally."""

    def test_all_engines_active_weights_sum_to_one(self) -> None:
        policy = DEFAULT_ENTERPRISE_POLICY
        active = {
            "security": True,
            "behavioral": True,
            "ml": True,
            "llm": True,
            "threat_intel": True,
        }
        weights = compute_effective_weights(policy, active)
        total = sum(weights.values())
        assert pytest.approx(total, abs=1e-3) == 1.0
        assert weights["security"] == pytest.approx(0.35, abs=1e-3)
        assert weights["ml"] == pytest.approx(0.25, abs=1e-3)

    def test_llm_inactive_redistributes_weights(self) -> None:
        policy = DEFAULT_ENTERPRISE_POLICY
        active = {
            "security": True,
            "behavioral": True,
            "ml": True,
            "llm": False,  # e.g. unconfigured or timed out
            "threat_intel": True,
        }
        weights = compute_effective_weights(policy, active)
        total = sum(weights.values())
        assert pytest.approx(total, abs=1e-3) == 1.0
        assert weights["llm"] == 0.0
        # Active weights must increase proportionally
        assert weights["security"] > policy.security_weight
        assert weights["ml"] > policy.ml_weight

    def test_ti_and_llm_inactive_redistributes_weights(self) -> None:
        policy = DEFAULT_ENTERPRISE_POLICY
        active = {
            "security": True,
            "behavioral": True,
            "ml": True,
            "llm": False,
            "threat_intel": False,
        }
        weights = compute_effective_weights(policy, active)
        total = sum(weights.values())
        assert pytest.approx(total, abs=1e-3) == 1.0
        assert weights["llm"] == 0.0
        assert weights["threat_intel"] == 0.0
        assert weights["security"] > policy.security_weight

    def test_fallback_when_no_components_active(self) -> None:
        policy = DEFAULT_ENTERPRISE_POLICY
        active = {
            "security": False,
            "behavioral": False,
            "ml": False,
            "llm": False,
            "threat_intel": False,
        }
        weights = compute_effective_weights(policy, active)
        assert weights["security"] == 1.0


# ===========================================================================
# 3. Hard Security Invariants Tests (Prevent Contradictory LLM Overrides)
# ===========================================================================


class TestHardSecurityFloors:
    """Verify that hard forensic signals cannot be silently overridden by an LLM."""

    def test_critical_malware_attachment_not_overridden_by_benign_llm(self) -> None:
        """When an email has a weaponized attachment, a benign LLM response must not lower the score."""
        engine = RiskEngine()

        # Hard forensic finding: executable attachment
        malware_signal = _make_signal(
            source="attachment_analyzer",
            signal_type="EXECUTABLE_ATTACHMENT",
            category=ThreatCategory.MALWARE,
            severity=ThreatSeverity.CRITICAL,
            attack_type=AttackType.MALICIOUS_DOCUMENT,
            score=95.0,
            confidence=0.98,
            title="Dangerous Executable Attachment",
        )

        # Contradictory LLM response: LLM fell for prompt injection and said "benign"
        benign_llm = _make_llm_result(
            classification=LLMIntentClassification.BENIGN,
            confidence=0.95,
            is_phishing_intent=False,
            is_credential_request=False,
            tactics=[],
            impersonation_target=None,
        )

        # ML model might also be uncertain on a novel lure
        ml_clean = _make_ml_result(
            classification="clean", phishing_probability=0.1, clean_probability=0.9
        )

        assessment = engine.assess(
            security_signals=[malware_signal],
            ml_result=ml_clean,
            llm_result=benign_llm,
        )

        # Hard floor must enforce minimum score >= 85.0 and CRITICAL severity
        assert assessment.risk_score >= 85.0
        assert assessment.severity == ThreatSeverity.CRITICAL
        assert assessment.risk_level == RiskLevel.CRITICAL
        assert assessment.verdict == AnalysisVerdict.BLOCK
        assert assessment.hard_floor_applied is True
        assert assessment.hard_floor_reason is not None
        assert (
            "safely overridden" in assessment.hard_floor_reason.lower()
            or "critical hard signal" in assessment.hard_floor_reason.lower()
        )
        assert assessment.classification == ThreatCategory.MALWARE

    def test_malicious_threat_intel_ioc_not_overridden_by_benign_llm(self) -> None:
        """When Threat Intel flags a confirmed malicious IOC, a benign LLM must not suppress it."""
        engine = RiskEngine()

        ti_signal = _make_ti_signal(
            indicator_value="evil-c2-harvest.net",
            verdict=ReputationVerdict.MALICIOUS,
            threat_score=100.0,
            confidence=0.98,
        )

        benign_llm = _make_llm_result(
            classification=LLMIntentClassification.BENIGN,
            confidence=0.90,
            is_phishing_intent=False,
        )

        assessment = engine.assess(
            threat_intel_signals=[ti_signal],
            llm_result=benign_llm,
        )

        assert assessment.risk_score >= 85.0
        assert assessment.severity == ThreatSeverity.CRITICAL
        assert assessment.verdict == AnalysisVerdict.BLOCK
        assert assessment.hard_floor_applied is True

    def test_high_auth_failure_not_overridden_by_benign_llm(self) -> None:
        """SPF hard fail + spoofing must enforce high floor (>= 70.0) despite benign LLM."""
        engine = RiskEngine()

        spf_signal = _make_signal(
            source="authentication_analyzer",
            signal_type="SPF_FAIL",
            category=ThreatCategory.PHISHING,
            severity=ThreatSeverity.HIGH,
            attack_type=AttackType.SPOOFING,
            score=75.0,
            confidence=0.95,
            title="SPF Hard Fail",
        )

        benign_llm = _make_llm_result(
            classification=LLMIntentClassification.BENIGN,
            confidence=0.90,
            is_phishing_intent=False,
        )

        assessment = engine.assess(
            security_signals=[spf_signal],
            llm_result=benign_llm,
        )

        # High floor enforced: score >= 70.0, severity HIGH, verdict QUARANTINE
        assert assessment.risk_score >= 70.0
        assert assessment.severity == ThreatSeverity.HIGH
        assert assessment.verdict == AnalysisVerdict.QUARANTINE
        assert assessment.hard_floor_applied is True

    def test_policy_disable_hard_floor_respected(self) -> None:
        """If a policy explicitly disables hard floors, raw composite score is returned."""
        permissive_no_floor_policy = RiskPolicy(
            name="test_no_floor",
            enforce_critical_hard_floor=False,
            enforce_high_hard_floor=False,
        )
        engine = RiskEngine(default_policy=permissive_no_floor_policy)

        malware_signal = _make_signal(severity=ThreatSeverity.CRITICAL, score=90.0, confidence=0.9)
        benign_llm = _make_llm_result(
            classification=LLMIntentClassification.BENIGN, confidence=0.95, is_phishing_intent=False
        )
        ml_clean = _make_ml_result(classification="clean", clean_probability=0.95)

        assessment = engine.assess(
            security_signals=[malware_signal],
            ml_result=ml_clean,
            llm_result=benign_llm,
            policy=permissive_no_floor_policy,
        )

        # Since floors were disabled, the raw weighted average without floor is used
        assert assessment.hard_floor_applied is False


# ===========================================================================
# 4. Configurable Risk Policies Tests
# ===========================================================================


class TestRiskPolicyConfigurability:
    """Validate policy customization and preset behaviors."""

    def test_default_enterprise_policy_thresholds(self) -> None:
        p = DEFAULT_ENTERPRISE_POLICY
        assert p.critical_threshold == 85.0
        assert p.high_threshold == 65.0
        assert p.medium_threshold == 40.0
        assert p.low_threshold == 20.0
        assert p.critical_action == "block"
        assert p.high_action == "quarantine"

    def test_zero_trust_policy_lower_quarantine_threshold(self) -> None:
        p = ZERO_TRUST_AGGRESSIVE_POLICY
        assert p.high_threshold == 55.0  # Quarantines at 55.0 vs 65.0 default
        assert p.critical_threshold == 80.0
        assert p.security_weight == 0.40

    def test_permissive_policy_higher_quarantine_threshold(self) -> None:
        p = PERMISSIVE_POLICY
        assert p.high_threshold == 75.0  # Quarantines only at 75.0+ to prevent FP
        assert p.critical_threshold == 90.0

    def test_custom_policy_weights_shift_score_predictably(self) -> None:
        """Custom policy with 80% weight on ML shifts composite score toward ML."""
        ml_heavy_policy = RiskPolicy(
            name="ml_heavy",
            ml_weight=0.80,
            security_weight=0.10,
            behavioral_weight=0.05,
            llm_weight=0.025,
            threat_intel_weight=0.025,
            enforce_critical_hard_floor=False,
            enforce_high_hard_floor=False,
        )
        engine = RiskEngine()

        ml_high = _make_ml_result(classification="phishing", phishing_probability=0.95)
        sec_low = _make_signal(severity=ThreatSeverity.LOW, score=20.0, confidence=0.8)

        assessment = engine.assess(
            security_signals=[sec_low],
            ml_result=ml_high,
            policy=ml_heavy_policy,
        )

        # ML 80% should pull score near 80+
        assert assessment.risk_score >= 70.0
        assert assessment.policy_name == "ml_heavy"

    def test_all_thresholds_documented(self) -> None:
        """Ensure threshold fields in RiskPolicy have comprehensive docstrings."""
        schema = RiskPolicy.model_json_schema()
        properties = schema.get("properties", {})

        for field in ("critical_threshold", "high_threshold", "medium_threshold", "low_threshold"):
            assert field in properties
            description = properties[field].get("description", "")
            assert len(description) > 20
            assert "Rationale:" in description


# ===========================================================================
# 5. Threat Taxonomy and Classification Tests
# ===========================================================================


class TestTaxonomyAndClassification:
    """Validate ThreatCategory and AttackType resolution across multi-engine consensus."""

    def test_malware_attachment_resolves_to_malware(self) -> None:
        engine = RiskEngine()
        malware_sig = _make_signal(
            source="attachment_analyzer",
            signal_type="EXECUTABLE_ATTACHMENT",
            category=ThreatCategory.MALWARE,
            severity=ThreatSeverity.CRITICAL,
            attack_type=AttackType.MALICIOUS_DOCUMENT,
        )
        assessment = engine.assess(security_signals=[malware_sig])
        assert assessment.classification == ThreatCategory.MALWARE
        assert assessment.attack_type == AttackType.MALICIOUS_DOCUMENT

    def test_bec_with_payment_request_resolves_to_bec(self) -> None:
        engine = RiskEngine()
        bec_llm = _make_llm_result(
            classification=LLMIntentClassification.BUSINESS_EMAIL_COMPROMISE,
            is_phishing_intent=True,
            is_bec_intent=True,
            is_payment_request=True,
            impersonation_target="CEO John Doe",
        )
        assessment = engine.assess(llm_result=bec_llm)
        assert assessment.classification == ThreatCategory.BUSINESS_EMAIL_COMPROMISE
        assert assessment.attack_type in (AttackType.SPEAR_PHISHING, AttackType.WHALING)

    def test_credential_harvesting_resolves_to_credential_theft(self) -> None:
        engine = RiskEngine()
        cred_sig = _make_signal(
            source="url_analyzer",
            signal_type="CREDENTIAL_HARVESTING_URL",
            category=ThreatCategory.CREDENTIAL_THEFT,
            severity=ThreatSeverity.HIGH,
            attack_type=AttackType.CREDENTIAL_HARVESTING,
        )
        assessment = engine.assess(security_signals=[cred_sig])
        assert assessment.classification == ThreatCategory.CREDENTIAL_THEFT
        assert assessment.attack_type == AttackType.CREDENTIAL_HARVESTING

    def test_clean_email_resolves_to_unknown_category(self) -> None:
        engine = RiskEngine()
        clean_ml = _make_ml_result(
            classification="clean", clean_probability=0.98, phishing_probability=0.01
        )
        clean_llm = _make_llm_result(
            classification=LLMIntentClassification.BENIGN,
            is_phishing_intent=False,
            is_credential_request=False,
            confidence=0.95,
        )
        assessment = engine.assess(ml_result=clean_ml, llm_result=clean_llm)
        assert assessment.classification == ThreatCategory.UNKNOWN
        assert assessment.severity in (ThreatSeverity.INFO, ThreatSeverity.LOW)
        assert assessment.verdict == AnalysisVerdict.CLEAN
        assert assessment.recommendation == "allow"


# ===========================================================================
# 6. Complete RiskAssessment Contract & Explainability Tests
# ===========================================================================


class TestRiskAssessmentOutputContract:
    """Validate all output fields, explainable evidence, and audit narrative."""

    def test_full_contract_fields_and_types(self) -> None:
        engine = RiskEngine()
        sig = _make_signal()
        ml = _make_ml_result()
        llm = _make_llm_result()
        ti = _make_ti_signal()

        assessment = engine.assess(
            security_signals=[sig],
            ml_result=ml,
            llm_result=llm,
            threat_intel_signals=[ti],
        )

        assert isinstance(assessment, RiskAssessment)
        assert 0.0 <= assessment.risk_score <= 100.0
        assert isinstance(assessment.severity, ThreatSeverity)
        assert isinstance(assessment.risk_level, RiskLevel)
        assert isinstance(assessment.verdict, AnalysisVerdict)
        assert 0.0 <= assessment.confidence <= 1.0
        assert isinstance(assessment.classification, ThreatCategory)
        assert isinstance(assessment.attack_type, AttackType)
        assert isinstance(assessment.signals, list)
        assert isinstance(assessment.evidence, list)
        assert isinstance(assessment.recommendation, str)
        assert assessment.engine_version == RiskEngine.ENGINE_VERSION
        assert isinstance(assessment.subscores, RiskSubscores)
        assert isinstance(assessment.weights_applied, dict)
        assert isinstance(assessment.policy_name, str)
        assert isinstance(assessment.hard_floor_applied, bool)
        assert isinstance(assessment.rationale, str)
        assert len(assessment.rationale) > 20

    def test_evidence_items_compiled_across_all_active_sources(self) -> None:
        engine = RiskEngine()
        sig = _make_signal(source="sender_analyzer")
        beh = _make_signal(source="behavior_analyzer", signal_type="URGENCY_LURE")
        ml = _make_ml_result()
        llm = _make_llm_result()
        ti = _make_ti_signal()

        assessment = engine.assess(
            security_signals=[sig],
            behavioral_signals=[beh],
            ml_result=ml,
            llm_result=llm,
            threat_intel_signals=[ti],
        )

        sources_represented = {e.source for e in assessment.evidence}
        assert EngineSource.SECURITY_ENGINE in sources_represented
        assert EngineSource.BEHAVIORAL_ANALYSIS in sources_represented
        assert EngineSource.ML_ENGINE in sources_represented
        assert EngineSource.GROQ_LLM in sources_represented
        assert EngineSource.THREAT_INTEL in sources_represented

    def test_rationale_documents_risk_drivers_and_weights(self) -> None:
        engine = RiskEngine()
        sig = _make_signal(score=80.0)
        ml = _make_ml_result(phishing_probability=0.90)

        assessment = engine.assess(security_signals=[sig], ml_result=ml)

        rationale = assessment.rationale
        assert "Assigned risk score" in rationale
        assert "Security Engine" in rationale
        assert "ML Classifier" in rationale

    def test_confidence_consensus_bonus(self) -> None:
        """When 3 or more engines agree, blended confidence receives a consensus multiplier."""
        sig = _make_signal(confidence=0.85)
        ml = _make_ml_result(confidence=0.85)
        llm = _make_llm_result(confidence=0.85)
        ti = _make_ti_signal(confidence=0.85)

        active = {"security": True, "ml": True, "llm": True, "threat_intel": True}
        blended = compute_blended_confidence(
            active_components=active,
            signals=[sig],
            ml_result=ml,
            llm_result=llm,
            ti_items=[ti],
        )

        # Baseline confidence is 0.85; with >= 3 agreeing engines, it gets multiplied by 1.05
        assert blended > 0.85
        assert blended <= 1.0


# ===========================================================================
# 7. Multi-Engine Fusion Tests
# ===========================================================================


class TestMultiEngineFusion:
    """Validate that no single engine dictates the outcome without hard signals."""

    def test_isolated_ml_does_not_unilaterally_force_critical(self) -> None:
        """High ML score alone with all other engines clean results in High/Suspicious, not Critical."""
        engine = RiskEngine()
        ml_phish = _make_ml_result(phishing_probability=0.88, confidence=0.85)
        llm_benign = _make_llm_result(
            classification=LLMIntentClassification.BENIGN,
            is_phishing_intent=False,
            confidence=0.90,
        )

        assessment = engine.assess(
            security_signals=[],  # No security signals
            ml_result=ml_phish,
            llm_result=llm_benign,
        )

        # ML alone cannot push score to 85+ (Critical) when LLM is benign and security is clean
        assert assessment.risk_score < 85.0
        assert assessment.severity != ThreatSeverity.CRITICAL

    def test_compounding_weak_signals_escalate_composite_risk(self) -> None:
        """Multiple moderate/weak signals across engines compound into a elevated risk."""
        engine = RiskEngine()

        # Moderate security signal
        sec_signal = _make_signal(severity=ThreatSeverity.MEDIUM, score=45.0, confidence=0.8)
        # Moderate ML signal
        ml_mod = _make_ml_result(phishing_probability=0.70, confidence=0.75)
        # Moderate LLM signal
        llm_mod = _make_llm_result(
            classification=LLMIntentClassification.SOCIAL_ENGINEERING,
            confidence=0.75,
            is_phishing_intent=True,
            is_credential_request=False,
        )

        assessment = engine.assess(
            security_signals=[sec_signal],
            ml_result=ml_mod,
            llm_result=llm_mod,
        )

        # Compounded score should be elevated above individual signals and cross medium threshold
        assert assessment.risk_score >= 40.0
        assert assessment.severity in (ThreatSeverity.MEDIUM, ThreatSeverity.HIGH)

    def test_completely_clean_email_across_all_engines(self) -> None:
        """When all engines report clean, composite score is near zero and verdict is CLEAN."""
        engine = RiskEngine()

        ml_clean = _make_ml_result(
            classification="clean", clean_probability=0.99, phishing_probability=0.01
        )
        llm_clean = _make_llm_result(
            classification=LLMIntentClassification.BENIGN,
            confidence=0.98,
            is_phishing_intent=False,
            is_credential_request=False,
            tactics=[],
            impersonation_target=None,
        )
        ti_clean = _make_ti_signal(verdict=ReputationVerdict.CLEAN, threat_score=0.0)

        assessment = engine.assess(
            security_signals=[],
            behavioral_signals=[],
            ml_result=ml_clean,
            llm_result=llm_clean,
            threat_intel_signals=[ti_clean],
        )

        assert assessment.risk_score <= 15.0
        assert assessment.severity in (ThreatSeverity.INFO, ThreatSeverity.LOW)
        assert assessment.risk_level in (RiskLevel.SAFE, RiskLevel.LOW)
        assert assessment.verdict == AnalysisVerdict.CLEAN
        assert assessment.recommendation in ("allow", "allow_with_banner")
        assert assessment.hard_floor_applied is False
