"""LLM Analyzer — public-facing orchestrator for the LLM analysis layer.

Responsibilities:
- Accept ``EmailAnalysisInput`` and optional deterministic signals.
- Build ``deterministic_context`` dict from ``NormalizedThreatSignal`` list.
- Delegate to ``GroqProvider`` for semantic intent analysis.
- Return typed ``LLMResult`` (never raises; always returns structured output).
- Remains async-compatible for FastAPI request handlers and background workers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from app.domain.entities.email_analysis_input import EmailAnalysisInput
from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.services.llm.groq_provider import GroqProvider
from app.services.llm.schemas import LLMResult

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)


class LLMAnalyzer:
    """Orchestrator that bridges the deterministic pipeline and the Groq LLM provider.

    This is the single entry-point component that external code (API routes,
    background workers, analysis orchestrators) should use.  It is NOT a thin
    alias — it is responsible for:

    1. Transforming ``NormalizedThreatSignal`` objects into the structured
       ``deterministic_context`` dict that the prompt builder needs.
    2. Calling ``GroqProvider.analyze()`` and propagating the result.
    3. Structured logging at the boundary between pipeline stages.
    """

    def __init__(self, provider: GroqProvider | None = None) -> None:
        self._provider = provider or GroqProvider()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze(
        self,
        email_input: EmailAnalysisInput,
        threat_signals: list[NormalizedThreatSignal] | None = None,
    ) -> LLMResult:
        """Run LLM semantic analysis on a preprocessed email.

        Args:
            email_input: Canonical preprocessed email produced by
                ``EmailPreprocessingPipeline``.
            threat_signals: Optional list of ``NormalizedThreatSignal``
                objects emitted by the deterministic analysis engine.
                These are converted to a concise context string supplied to
                the prompt so the LLM has forensic grounding.

        Returns:
            ``LLMResult`` — always returned; never raises.  On any failure
            the provider's fallback path fires and ``status`` reflects the
            error class (``"timeout"``, ``"api_error"``, ``"fallback"``).
        """
        deterministic_context = self._build_deterministic_context(threat_signals)

        logger.info(
            "llm_analysis_started",
            email_id=email_input.analysis_input_id,
            signal_count=len(threat_signals) if threat_signals else 0,
            has_deterministic_context=bool(deterministic_context),
        )

        result = await self._provider.analyze(
            email_input=email_input,
            deterministic_context=deterministic_context if deterministic_context else None,
        )

        logger.info(
            "llm_analysis_completed",
            email_id=email_input.analysis_input_id,
            provider=result.provider,
            model=result.model,
            status=result.status,
            classification=result.classification,
            confidence=result.confidence,
            latency_ms=result.latency_ms,
        )

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_deterministic_context(
        signals: list[NormalizedThreatSignal] | None,
    ) -> dict[str, str]:
        """Convert deterministic threat signals into a factual context dict.

        Only high/critical signals are surfaced so the prompt stays concise.
        Each entry is keyed by ``signal_type`` with a compact summary value.

        The LLM is instructed to treat these as immutable forensic facts — not
        to re-derive them or contradict them.
        """
        if not signals:
            return {}

        # Deduplicate by signal_type, keeping the highest-severity entry
        _severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        best: dict[str, NormalizedThreatSignal] = {}
        for sig in signals:
            existing = best.get(sig.signal_type)
            if existing is None:
                best[sig.signal_type] = sig
            else:
                if _severity_rank.get(sig.severity, 0) > _severity_rank.get(existing.severity, 0):
                    best[sig.signal_type] = sig

        # Include only medium/high/critical signals to avoid prompt bloat
        context: dict[str, str] = {}
        for signal_type, sig in best.items():
            if _severity_rank.get(sig.severity, 0) >= _severity_rank["medium"]:
                # evidence is a dict[str, Any]; build a compact key=value summary
                if sig.evidence:
                    items = list(sig.evidence.items())[:2]
                    evidence_str = "; ".join(f"{k}={v}" for k, v in items)
                else:
                    evidence_str = sig.description
                context[signal_type] = f"[{sig.severity.upper()}] {sig.title}: {evidence_str}"

        return context
