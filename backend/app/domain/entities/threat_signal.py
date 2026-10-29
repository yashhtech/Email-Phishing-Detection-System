"""ThreatSignal entity returned by deterministic security analyzers.

Invariants:
1. Each analyzer produces ZERO or MORE NormalizedThreatSignal objects.
2. An analyzer NEVER makes a final verdict (CLEAN/SUSPICIOUS/MALICIOUS). It only reports signals.
3. Every signal is fully typed, normalized, and immutable (frozen).
4. Score is in [0.0, 100.0] representing the isolated risk contribution of that finding.
5. Confidence is in [0.0, 1.0] representing how certain the heuristic is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.infrastructure.db.models.enums import AttackType, ThreatCategory, ThreatSeverity


@dataclass(frozen=True)
class NormalizedThreatSignal:
    """Normalized threat signal produced by deterministic analyzers."""

    source: str  # e.g., 'sender_analyzer', 'authentication_analyzer', 'url_analyzer'
    signal_type: str  # e.g., 'SPF_FAIL', 'SPOOFED_DISPLAY_NAME', 'EXECUTABLE_ATTACHMENT'
    category: ThreatCategory  # e.g., ThreatCategory.PHISHING, ThreatCategory.MALWARE
    severity: ThreatSeverity  # ThreatSeverity.INFO, LOW, MEDIUM, HIGH, CRITICAL
    attack_type: AttackType  # AttackType.SPEAR_PHISHING, SPOOFING, etc.
    score: float  # [0.0, 100.0] sub-score risk contribution
    confidence: float  # [0.0, 1.0] detection confidence
    title: str  # Short readable finding summary
    description: str  # Detailed technical explanation
    evidence: dict[str, Any] = field(default_factory=dict)  # Forensic context / matching tokens
    metadata: dict[str, Any] = field(default_factory=dict)  # Telemetry, offsets, rules triggered
    indicator_value: str | None = None  # Specific IOC (IP, domain, URL, hash)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
