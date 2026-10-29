"""Groq LLM HTTP client wrapper using httpx.

Features:
- Pure asynchronous httpx client (compatible with FastAPI, background tasks, Celery)
- Bounded exponential backoff with jitter on 429 (Rate Limit) and 5xx (Server Error)
- Strict timeouts configurable via GROQ_TIMEOUT
- Never logs API keys, auth headers, or raw bodies
- Strips any accidental markdown code fence formatting from response before JSON parsing
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import time
from typing import Any

import httpx
import structlog
from pydantic import SecretStr

from app.infrastructure.config.settings import Settings, get_settings

logger = structlog.get_logger(__name__)

_GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


class GroqClientError(Exception):
    """Raised when Groq API request fails."""


class GroqTimeoutError(GroqClientError):
    """Raised when Groq API times out."""


class GroqClient:
    """Async HTTP client for Groq's OpenAI-compatible completions endpoint."""

    def __init__(
        self,
        api_key: SecretStr | None = None,
        model: str | None = None,
        timeout: int | None = None,
        max_retries: int | None = None,
    ) -> None:
        settings: Settings = get_settings()
        self._api_key = api_key or settings.groq_api_key
        self._model = model or settings.groq_model
        self._timeout = timeout if timeout is not None else settings.groq_timeout
        self._max_retries = max_retries if max_retries is not None else settings.groq_max_retries

    @property
    def is_configured(self) -> bool:
        """Return True if a valid API key is present."""
        return self._api_key is not None and bool(self._api_key.get_secret_value().strip())

    @property
    def model_name(self) -> str:
        return self._model

    async def chat_completion(
        self,
        system_instruction: str,
        user_prompt: str,
        temperature: float = 0.1,
    ) -> tuple[dict[str, Any], dict[str, int], float]:
        """Execute chat completion against Groq API with retries and timeout.

        Returns:
            Tuple of (parsed_json_dict, token_usage_dict, latency_ms).

        Raises:
            GroqClientError: on permanent failures or malformed responses.
            GroqTimeoutError: on request timeouts after retries exhausted.
        """
        if not self.is_configured:
            raise GroqClientError("GROQ_API_KEY is not configured in environment.")

        headers = {
            "Authorization": f"Bearer {self._api_key.get_secret_value()}",  # type: ignore[union-attr]
            "Content-Type": "application/json",
        }

        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "response_format": {"type": "json_object"},
        }

        start_time = time.perf_counter()
        last_error: Exception | None = None

        # Retry loop with exponential backoff
        for attempt in range(self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=float(self._timeout)) as client:
                    response = await client.post(_GROQ_API_URL, headers=headers, json=payload)

                if response.status_code == 200:
                    latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                    data = response.json()
                    raw_content = data["choices"][0]["message"]["content"]
                    usage = data.get("usage", {})
                    token_usage = {
                        "prompt_tokens": usage.get("prompt_tokens", 0),
                        "completion_tokens": usage.get("completion_tokens", 0),
                        "total_tokens": usage.get("total_tokens", 0),
                    }
                    parsed_json = self._clean_and_parse_json(raw_content)
                    return parsed_json, token_usage, latency_ms

                # Check if retryable (429 or 5xx)
                if response.status_code in (429, 500, 502, 503, 504):
                    if attempt < self._max_retries:
                        delay = (2**attempt) + random.uniform(0.1, 0.5)
                        logger.warning(
                            "groq_api_retryable_error",
                            status_code=response.status_code,
                            attempt=attempt + 1,
                            delay=round(delay, 2),
                        )
                        await asyncio.sleep(delay)
                        continue

                # Non-retryable HTTP error
                raise GroqClientError(
                    f"Groq API returned HTTP {response.status_code}: {response.text[:200]}"
                )

            except httpx.TimeoutException as exc:
                last_error = exc
                if attempt < self._max_retries:
                    delay = (2**attempt) + 0.2
                    logger.warning("groq_api_timeout_retrying", attempt=attempt + 1, delay=delay)
                    await asyncio.sleep(delay)
                    continue
                raise GroqTimeoutError(
                    f"Groq API request timed out after {self._timeout}s across {self._max_retries + 1} attempts"
                ) from exc

            except (httpx.RequestError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt < self._max_retries:
                    await asyncio.sleep(1.0)
                    continue
                raise GroqClientError(f"Groq request failed: {exc}") from exc

        raise GroqClientError(f"Groq retries exhausted: {last_error}")

    @staticmethod
    def _clean_and_parse_json(text: str) -> dict[str, Any]:
        """Strip markdown fences (```json ... ```) and parse JSON safely."""
        cleaned = text.strip()
        # Remove opening markdown code block if present
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r"\s*```$", "", cleaned)
        return json.loads(cleaned)  # type: ignore[no-any-return]
