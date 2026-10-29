"""Configurable risk policies and documented threshold definitions.

Architectural Principles:
1. No arbitrary thresholds: Every numerical threshold is explicitly documented with
   operational justification and security rationale.
2. Configurable weights: Multi-engine weighting is fully customizable per tenant or policy.
3. Hard Security Invariants: Hard forensic signals (e.g. malware attachments, confirmed IOCs,
   cryptographic auth failure with impersonation) trigger immutable risk floors that cannot
   be silently overridden or diluted by ambiguous or contradictory LLM assessments.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RiskPolicy(BaseModel):
    """Authoritative risk policy governing weighting, thresholds, and safety invariants."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(
        default="default_enterprise",
        description="Unique policy identifier",
    )
    description: str = Field(
        default="Balanced enterprise risk policy with robust multi-engine fusion.",
        description="Human-readable policy rationale",
    )

    # -------------------------------------------------------------------------
    # Configurable Engine Weights (Sum typically 1.0; dynamically normalized if a component is inactive)
    # -------------------------------------------------------------------------
    security_weight: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
        description=(
            "Weight for deterministic security engine findings (headers, auth, URL, domain, attachment). "
            "Forensically grounded facts receive the largest primary weighting (35%)."
        ),
    )
    ml_weight: float = Field(
        default=0.25,
        ge=0.0,
        le=1.0,
        description=(
            "Weight for statistical ML classification. "
            "Evaluates 30 engineered email features using calibrated models (25%)."
        ),
    )
    llm_weight: float = Field(
        default=0.15,
        ge=0.0,
        le=1.0,
        description=(
            "Weight for Groq LLM semantic intent analysis. "
            "Evaluates psychological manipulation, social engineering, and impersonation lures (15%)."
        ),
    )
    threat_intel_weight: float = Field(
        default=0.15,
        ge=0.0,
        le=1.0,
        description=(
            "Weight for external and internal threat intelligence reputation feeds and IOC blocklists (15%)."
        ),
    )
    behavioral_weight: float = Field(
        default=0.10,
        ge=0.0,
        le=1.0,
        description=(
            "Weight for behavioral email anomalies (urgency coercion, zero-font evasion, deceptive anchors) (10%)."
        ),
    )

    # -------------------------------------------------------------------------
    # Documented Risk Thresholds
    # -------------------------------------------------------------------------
    critical_threshold: float = Field(
        default=85.0,
        ge=0.0,
        le=100.0,
        description=(
            "Threshold >= 85.0 designates CRITICAL risk (verdict: BLOCK). "
            "Rationale: Confirmed active threats such as weaponized attachments, active credential theft, "
            "or multi-vector BEC requiring automated blocking or immediate administrative quarantine."
        ),
    )
    high_threshold: float = Field(
        default=65.0,
        ge=0.0,
        le=100.0,
        description=(
            "Threshold >= 65.0 designates HIGH risk (verdict: QUARANTINE). "
            "Rationale: Strong forensic or semantic evidence of phishing or impersonation "
            "(e.g., auth failure paired with brand lookalike, or high ML confidence) "
            "warranting message isolation from the recipient inbox."
        ),
    )
    medium_threshold: float = Field(
        default=40.0,
        ge=0.0,
        le=100.0,
        description=(
            "Threshold >= 40.0 designates MEDIUM risk (verdict: SUSPICIOUS). "
            "Rationale: Ambiguous risk signals (e.g., unverified sender, external links with redirectors, "
            "or urgency language without confirmed payload) requiring a security warning banner or review."
        ),
    )
    low_threshold: float = Field(
        default=20.0,
        ge=0.0,
        le=100.0,
        description=(
            "Threshold >= 20.0 designates LOW risk (verdict: CLEAN with informational monitoring). "
            "Rationale: Minor informational anomalies (e.g., promotional trackers, missing optional headers) "
            "that do not represent an active attack."
        ),
    )

    # -------------------------------------------------------------------------
    # Hard Security Invariants (Floors that prevent contradictory LLM overrides)
    # -------------------------------------------------------------------------
    enforce_critical_hard_floor: bool = Field(
        default=True,
        description=(
            "When True, any verified CRITICAL hard signal (malicious executable attachment, "
            "known malware hash, or confirmed malicious IOC) enforces a minimum composite score "
            "of at least critical_floor_score, regardless of any LLM or ML assertions."
        ),
    )
    critical_floor_score: float = Field(
        default=85.0,
        ge=0.0,
        le=100.0,
        description="Minimum risk score enforced when a CRITICAL hard security signal is present.",
    )

    enforce_high_hard_floor: bool = Field(
        default=True,
        description=(
            "When True, verified severe authentication failure (SPF hard fail + DKIM fail + DMARC reject) "
            "or severe brand impersonation enforces a minimum composite score of at least high_floor_score."
        ),
    )
    high_floor_score: float = Field(
        default=70.0,
        ge=0.0,
        le=100.0,
        description="Minimum risk score enforced when high-severity hard auth/spoofing signals are present.",
    )

    prohibit_llm_override: bool = Field(
        default=True,
        description=(
            "Strict invariant: If hard security signals exist, an LLM assessment of 'benign' or 'clean' "
            "is strictly forbidden from lowering the risk score or downgrading severity below the active floor."
        ),
    )

    # -------------------------------------------------------------------------
    # Action Recommendation Mappings
    # -------------------------------------------------------------------------
    critical_action: str = Field(
        default="block", description="Action recommendation for CRITICAL severity"
    )
    high_action: str = Field(
        default="quarantine", description="Action recommendation for HIGH severity"
    )
    medium_action: str = Field(
        default="alert_user", description="Action recommendation for MEDIUM severity"
    )
    low_action: str = Field(
        default="allow_with_banner", description="Action recommendation for LOW severity"
    )
    safe_action: str = Field(
        default="allow", description="Action recommendation for SAFE/CLEAN status"
    )


# -----------------------------------------------------------------------------
# Pre-Configured Standard Policy Presets
# -----------------------------------------------------------------------------

DEFAULT_ENTERPRISE_POLICY = RiskPolicy(
    name="default_enterprise",
    description="Standard enterprise policy: balanced multi-engine fusion with strict hard security floors.",
)

ZERO_TRUST_AGGRESSIVE_POLICY = RiskPolicy(
    name="zero_trust_aggressive",
    description="High-security zero-trust policy: increased deterministic/TI weighting, lower quarantine threshold (55.0).",
    security_weight=0.40,
    ml_weight=0.25,
    threat_intel_weight=0.20,
    llm_weight=0.10,
    behavioral_weight=0.05,
    critical_threshold=80.0,
    high_threshold=55.0,
    medium_threshold=35.0,
    low_threshold=15.0,
    critical_floor_score=88.0,
    high_floor_score=72.0,
)

PERMISSIVE_POLICY = RiskPolicy(
    name="permissive_sales",
    description="Permissive policy for marketing and sales teams: higher quarantine threshold (75.0) to minimize false positives.",
    security_weight=0.30,
    ml_weight=0.20,
    threat_intel_weight=0.15,
    llm_weight=0.25,
    behavioral_weight=0.10,
    critical_threshold=90.0,
    high_threshold=75.0,
    medium_threshold=50.0,
    low_threshold=25.0,
    critical_floor_score=85.0,
    high_floor_score=68.0,
)
