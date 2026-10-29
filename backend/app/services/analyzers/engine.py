"""Deterministic security analysis coordinator.

Orchestrates all 7 independent analyzers:
1. SenderAnalyzer
2. HeaderAnalyzer
3. AuthenticationAnalyzer
4. URLAnalyzer
5. DomainAnalyzer
6. AttachmentAnalyzer
7. BehaviorAnalyzer

Key invariants:
- Executes all 7 deterministic analyzers without relying on LLMs or external calls.
- Aggregates and returns the full list of NormalizedThreatSignal objects.
- Does NOT make the final threat verdict decision (verdicts and final risk scoring belong to scoring engines).
- Each analyzer can also be used individually and tested in total isolation.
"""

from __future__ import annotations

import structlog

from app.domain.entities.email_analysis_input import EmailAnalysisInput
from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.services.analyzers.attachment_analyzer import AttachmentAnalyzer
from app.services.analyzers.authentication_analyzer import AuthenticationAnalyzer
from app.services.analyzers.behavior_analyzer import BehaviorAnalyzer
from app.services.analyzers.domain_analyzer import DomainAnalyzer
from app.services.analyzers.header_analyzer import HeaderAnalyzer
from app.services.analyzers.sender_analyzer import SenderAnalyzer
from app.services.analyzers.url_analyzer import URLAnalyzer

logger = structlog.get_logger(__name__)


class DeterministicAnalysisEngine:
    """Coordinator running all 7 deterministic analyzers over an EmailAnalysisInput."""

    def __init__(
        self,
        sender_analyzer: SenderAnalyzer | None = None,
        header_analyzer: HeaderAnalyzer | None = None,
        authentication_analyzer: AuthenticationAnalyzer | None = None,
        url_analyzer: URLAnalyzer | None = None,
        domain_analyzer: DomainAnalyzer | None = None,
        attachment_analyzer: AttachmentAnalyzer | None = None,
        behavior_analyzer: BehaviorAnalyzer | None = None,
    ) -> None:
        self.sender_analyzer = sender_analyzer or SenderAnalyzer()
        self.header_analyzer = header_analyzer or HeaderAnalyzer()
        self.authentication_analyzer = authentication_analyzer or AuthenticationAnalyzer()
        self.url_analyzer = url_analyzer or URLAnalyzer()
        self.domain_analyzer = domain_analyzer or DomainAnalyzer()
        self.attachment_analyzer = attachment_analyzer or AttachmentAnalyzer()
        self.behavior_analyzer = behavior_analyzer or BehaviorAnalyzer()

    def run_all(self, email_input: EmailAnalysisInput) -> list[NormalizedThreatSignal]:
        """Run all 7 independent analyzers and return aggregated normalized threat signals."""
        signals: list[NormalizedThreatSignal] = []

        # 1. Sender
        signals.extend(self.sender_analyzer.analyze(email_input))

        # 2. Header
        signals.extend(self.header_analyzer.analyze(email_input))

        # 3. Authentication
        signals.extend(self.authentication_analyzer.analyze(email_input))

        # 4. URLs
        signals.extend(self.url_analyzer.analyze(email_input))

        # 5. Domains
        signals.extend(self.domain_analyzer.analyze(email_input))

        # 6. Attachments
        signals.extend(self.attachment_analyzer.analyze(email_input))

        # 7. Behavior
        signals.extend(self.behavior_analyzer.analyze(email_input))

        logger.info(
            "deterministic_analysis_completed",
            total_signals=len(signals),
            critical_signals=sum(1 for s in signals if s.severity.value == "critical"),
            high_signals=sum(1 for s in signals if s.severity.value == "high"),
            email_id=email_input.analysis_input_id,
        )

        return signals
