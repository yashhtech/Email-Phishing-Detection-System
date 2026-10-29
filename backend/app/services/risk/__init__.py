"""Risk Engine service package.

Public exports:
- RiskEngine: The primary coordinator for email risk assessment.
- RiskPolicy, DEFAULT_ENTERPRISE_POLICY, ZERO_TRUST_AGGRESSIVE_POLICY, PERMISSIVE_POLICY:
  Configurable risk evaluation policies and documented presets.
- RiskAssessment: Authoritative output contract containing composite score,
  severity, risk level, verdict, classification, attack type, signals, evidence, and rationale.
- ThreatEvidenceItem: Explainable audit item connecting concrete findings to risk impact.
- RiskSubscores: Normalized component subscore breakdown.
- ThreatIntelSignal: Standardized threat intelligence finding model.
- EngineSource: Taxonomy of signal-producing analysis engines.
"""

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
    ThreatEvidenceItem,
    ThreatIntelSignal,
)

__all__ = [
    "DEFAULT_ENTERPRISE_POLICY",
    "PERMISSIVE_POLICY",
    "ZERO_TRUST_AGGRESSIVE_POLICY",
    "EngineSource",
    "RiskAssessment",
    "RiskEngine",
    "RiskPolicy",
    "RiskSubscores",
    "ThreatEvidenceItem",
    "ThreatIntelSignal",
]
