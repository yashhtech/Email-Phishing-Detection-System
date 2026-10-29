"""Groq LLM provider implementation.

Adheres to a pluggable LLM provider protocol:
- Encapsulates prompt generation and response parsing
- Validates the structured output against Pydantic LLMAnalysisResponse
- Measures latency and returns typed LLMResult
- Implements graceful fallback if Groq is unconfigured or fails
"""

from __future__ import annotations

import time

import structlog

from app.domain.entities.email_analysis_input import EmailAnalysisInput
from app.services.llm.client import GroqClient, GroqClientError, GroqTimeoutError
from app.services.llm.prompts import SYSTEM_INSTRUCTION, build_analysis_prompt
from app.services.llm.safety import LLMSafetyFilter
from app.services.llm.schemas import (
    LLMAnalysisResponse,
    LLMIntentClassification,
    LLMResult,
)

logger = structlog.get_logger(__name__)


class GroqProvider:
    """Modular LLM provider integrating Groq API for email semantic analysis."""

    def __init__(self, client: GroqClient | None = None) -> None:
        self.client = client or GroqClient()

    @property
    def provider_name(self) -> str:
        return "groq"

    @property
    def model_name(self) -> str:
        return self.client.model_name

    async def analyze(
        self,
        email_input: EmailAnalysisInput,
        deterministic_context: dict[str, str] | None = None,
    ) -> LLMResult:
        """Run LLM semantic intent analysis on untrusted email data.

        Args:
            email_input: Canonical preprocessed email data.
            deterministic_context: Optional factual context from deterministic analyzers.

        Returns:
            Validated LLMResult (never throws; returns structured fallback on error).
        """
        start_time = time.perf_counter()

        # 1. Check if configured
        if not self.client.is_configured:
            logger.info("groq_unconfigured_returning_fallback")
            return self._build_unconfigured_fallback()

        # 2. Safety filter and prompt construction
        raw_body = email_input.content.normalized_plain or email_input.content.clean_text_for_ai
        sanitized_body = LLMSafetyFilter.sanitize_untrusted_text(raw_body)
        boundary_token = LLMSafetyFilter.generate_boundary_token()

        # Detect prompt injection attempts upfront
        is_injection, injection_cues = LLMSafetyFilter.detect_prompt_injection(raw_body)
        if is_injection:
            logger.warning(
                "prompt_injection_attempt_detected",
                email_id=email_input.analysis_input_id,
                cues=injection_cues,
            )

        prompt = build_analysis_prompt(
            subject=email_input.subject,
            from_address=email_input.sender.address,
            display_name=email_input.sender.display_name,
            sanitized_body=sanitized_body,
            boundary_token=boundary_token,
            deterministic_context=deterministic_context,
        )

        # 3. Call Groq with error handling
        try:
            parsed_json, usage, latency_ms = await self.client.chat_completion(
                system_instruction=SYSTEM_INSTRUCTION,
                user_prompt=prompt,
            )

            # 4. Strict Pydantic validation
            analysis_response = LLMAnalysisResponse.model_validate(parsed_json)

            # If prompt injection was detected upfront, ensure severity reflects it
            if is_injection and not analysis_response.is_phishing_intent:
                analysis_response = analysis_response.model_copy(
                    update={
                        "is_phishing_intent": True,
                        "classification": LLMIntentClassification.SOCIAL_ENGINEERING,
                        "threat_narrative": (
                            analysis_response.threat_narrative
                            + f" [SECURITY ALERT: Prompt injection attempt detected: {', '.join(injection_cues)}]"
                        ),
                    }
                )

            logger.info(
                "groq_analysis_completed",
                classification=analysis_response.classification.value,
                confidence=analysis_response.confidence,
                latency_ms=latency_ms,
                prompt_tokens=usage.get("prompt_tokens", 0),
            )

            return LLMResult(
                provider=self.provider_name,
                model=self.model_name,
                status="success",
                confidence=analysis_response.confidence,
                classification=analysis_response.classification.value,
                latency_ms=latency_ms,
                analysis=analysis_response,
                token_usage=usage,
            )

        except GroqTimeoutError as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.error("groq_request_timeout", error=str(exc), latency_ms=elapsed_ms)
            return self._build_error_fallback(
                status="timeout", error=str(exc), latency_ms=elapsed_ms
            )

        except GroqClientError as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.error("groq_request_failed", error=str(exc), latency_ms=elapsed_ms)
            return self._build_error_fallback(
                status="api_error", error=str(exc), latency_ms=elapsed_ms
            )

        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.error("groq_unexpected_failure", error=str(exc), latency_ms=elapsed_ms)
            return self._build_error_fallback(
                status="fallback", error=str(exc), latency_ms=elapsed_ms
            )

    def _build_unconfigured_fallback(self) -> LLMResult:
        """Fallback when GROQ_API_KEY is not set."""
        return LLMResult(
            provider=self.provider_name,
            model=self.model_name,
            status="unconfigured",
            confidence=0.0,
            classification=LLMIntentClassification.UNKNOWN.value,
            latency_ms=0.0,
            analysis=None,
            error_message="GROQ_API_KEY is not configured.",
        )

    def _build_error_fallback(self, status: str, error: str, latency_ms: float) -> LLMResult:
        """Safe fallback response when Groq encounters an error or timeout."""
        return LLMResult(
            provider=self.provider_name,
            model=self.model_name,
            status=status,
            confidence=0.0,
            classification=LLMIntentClassification.UNKNOWN.value,
            latency_ms=latency_ms,
            analysis=None,
            error_message=error,
        )
