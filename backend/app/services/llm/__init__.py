"""LLM service package.

Public exports for the LLM analysis layer:

- ``LLMAnalyzer``      — high-level orchestrator (use this from routes / workers)
- ``GroqProvider``     — direct Groq provider (inject a custom client for testing)
- ``GroqClient``       — low-level async HTTP client for the Groq API
- ``LLMResult``        — typed analysis result
- ``LLMAnalysisResponse`` — structured Pydantic model for the LLM JSON output
- ``LLMIntentClassification`` — StrEnum of supported intent categories
- ``LLMSafetyFilter``  — prompt injection defence utilities
"""

from app.services.llm.analyzer import LLMAnalyzer
from app.services.llm.client import GroqClient, GroqClientError, GroqTimeoutError
from app.services.llm.groq_provider import GroqProvider
from app.services.llm.safety import LLMSafetyFilter
from app.services.llm.schemas import (
    LLMAnalysisResponse,
    LLMIntentClassification,
    LLMResult,
)

__all__ = [
    "GroqClient",
    "GroqClientError",
    "GroqProvider",
    "GroqTimeoutError",
    "LLMAnalysisResponse",
    "LLMAnalyzer",
    "LLMIntentClassification",
    "LLMResult",
    "LLMSafetyFilter",
]
