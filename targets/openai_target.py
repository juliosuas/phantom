"""OpenAI target adapter for GPT-4, GPT-3.5-turbo, and compatible models."""

from __future__ import annotations

import logging
import os
from typing import Any

from targets.base import BaseTarget

logger = logging.getLogger(__name__)


class OpenAITarget(BaseTarget):
    """Send prompts to the OpenAI Chat Completions API.

    Parameters
    ----------
    model:
        Model identifier (e.g. ``"gpt-4"``, ``"gpt-3.5-turbo"``).
    api_key:
        OpenAI API key. Falls back to ``OPENAI_API_KEY`` env var.
    base_url:
        Optional custom base URL (for Azure OpenAI or compatible proxies).
    temperature:
        Sampling temperature. ``0.0`` for deterministic output.
    max_tokens:
        Maximum tokens in the completion.
    rate_limit_calls:
        Max requests per ``rate_limit_period`` seconds.
    rate_limit_period:
        Window length in seconds for rate limiting.
    max_retries:
        Number of retries on transient errors.
    """

    def __init__(
        self,
        model: str = "gpt-4",
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        *,
        rate_limit_calls: int = 60,
        rate_limit_period: float = 60.0,
        max_retries: int = 3,
    ) -> None:
        super().__init__(
            rate_limit_calls=rate_limit_calls,
            rate_limit_period=rate_limit_period,
            max_retries=max_retries,
        )
        try:
            import openai  # noqa: F811
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for OpenAITarget. "
                "Install it with: pip install openai"
            ) from exc

        resolved_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not resolved_key:
            raise ValueError(
                "An OpenAI API key must be provided via the api_key parameter "
                "or the OPENAI_API_KEY environment variable."
            )

        client_kwargs: dict[str, Any] = {"api_key": resolved_key}
        if base_url:
            client_kwargs["base_url"] = base_url

        self._client = openai.OpenAI(**client_kwargs)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def send(self, prompt: str, **kwargs: Any) -> str:
        """Send a single user message."""
        messages = [{"role": "user", "content": prompt}]
        return self._call_chat(messages, **kwargs)

    def send_with_system(
        self, system_prompt: str, prompt: str, **kwargs: Any
    ) -> str:
        """Send a user message preceded by a system instruction."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]
        return self._call_chat(messages, **kwargs)

    def send_multi_turn(
        self, messages: list[dict[str, str]], **kwargs: Any
    ) -> str:
        """Send an arbitrary conversation and return the assistant reply."""
        return self._call_chat(messages, **kwargs)

    def get_model_info(self) -> dict[str, Any]:
        return {
            "provider": "openai",
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "base_url": str(self._client.base_url),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_chat(
        self, messages: list[dict[str, str]], **kwargs: Any
    ) -> str:
        import openai as _openai

        temperature = kwargs.pop("temperature", self.temperature)
        max_tokens = kwargs.pop("max_tokens", self.max_tokens)

        start = self._pre_request()
        prompt_text = messages[-1].get("content", "") if messages else ""

        retryable = (
            _openai.RateLimitError,
            _openai.APIConnectionError,
            _openai.APITimeoutError,
            _openai.InternalServerError,
        )

        def _do_request() -> str:
            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=messages,  # type: ignore[arg-type]
                    temperature=temperature,
                    max_tokens=max_tokens,
                    **kwargs,
                )
                content = response.choices[0].message.content or ""
                self._log_request(
                    start,
                    prompt_text,
                    response=content,
                    model=self.model,
                    usage=getattr(response, "usage", None),
                )
                return content
            except _openai.BadRequestError as exc:
                # Content-filter or invalid request -- not retryable.
                self._log_request(
                    start, prompt_text, error=str(exc), model=self.model
                )
                raise
            except retryable:
                raise  # Let retry wrapper handle these.
            except _openai.APIError as exc:
                self._log_request(
                    start, prompt_text, error=str(exc), model=self.model
                )
                raise

        try:
            return self._retry_with_backoff(
                _do_request, retryable_exceptions=retryable
            )
        except retryable as exc:
            self._log_request(
                start, prompt_text, error=str(exc), model=self.model
            )
            raise
