"""Anthropic target adapter for Claude models."""

from __future__ import annotations

import logging
import os
from typing import Any

from targets.base import BaseTarget

logger = logging.getLogger(__name__)


class AnthropicTarget(BaseTarget):
    """Send prompts to the Anthropic Messages API.

    Parameters
    ----------
    model:
        Model identifier (e.g. ``"claude-sonnet-4-20250514"``).
    api_key:
        Anthropic API key. Falls back to ``ANTHROPIC_API_KEY`` env var.
    temperature:
        Sampling temperature.
    max_tokens:
        Maximum tokens in the response.
    rate_limit_calls:
        Max requests per ``rate_limit_period`` seconds.
    rate_limit_period:
        Window length in seconds for rate limiting.
    max_retries:
        Number of retries on transient errors.
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        api_key: str | None = None,
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
            import anthropic  # noqa: F811
        except ImportError as exc:
            raise ImportError(
                "The 'anthropic' package is required for AnthropicTarget. "
                "Install it with: pip install anthropic"
            ) from exc

        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise ValueError(
                "An Anthropic API key must be provided via the api_key parameter "
                "or the ANTHROPIC_API_KEY environment variable."
            )

        self._client = anthropic.Anthropic(api_key=resolved_key)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def send(self, prompt: str, **kwargs: Any) -> str:
        """Send a single user message (no system prompt)."""
        messages = [{"role": "user", "content": prompt}]
        return self._call_messages(messages, system_prompt=None, **kwargs)

    def send_with_system(
        self, system_prompt: str, prompt: str, **kwargs: Any
    ) -> str:
        """Send a user message with a system instruction.

        Anthropic's API accepts the system prompt as a dedicated parameter
        rather than as a message role, which is handled here.
        """
        messages = [{"role": "user", "content": prompt}]
        return self._call_messages(
            messages, system_prompt=system_prompt, **kwargs
        )

    def send_multi_turn(
        self, messages: list[dict[str, str]], **kwargs: Any
    ) -> str:
        """Send a multi-turn conversation.

        If the first message has role ``"system"``, it is extracted and
        passed as the ``system`` parameter to the API.
        """
        system_prompt: str | None = None
        conversation = list(messages)
        if conversation and conversation[0].get("role") == "system":
            system_prompt = conversation.pop(0).get("content", "")
        return self._call_messages(
            conversation, system_prompt=system_prompt, **kwargs
        )

    def get_model_info(self) -> dict[str, Any]:
        return {
            "provider": "anthropic",
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_messages(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> str:
        import anthropic as _anthropic

        temperature = kwargs.pop("temperature", self.temperature)
        max_tokens = kwargs.pop("max_tokens", self.max_tokens)

        start = self._pre_request()
        prompt_text = messages[-1].get("content", "") if messages else ""

        retryable = (
            _anthropic.RateLimitError,
            _anthropic.APIConnectionError,
            _anthropic.APITimeoutError,
            _anthropic.InternalServerError,
        )

        def _do_request() -> str:
            api_kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                **kwargs,
            }
            if system_prompt:
                api_kwargs["system"] = system_prompt

            try:
                response = self._client.messages.create(**api_kwargs)
                # Anthropic returns a list of content blocks.
                text_parts = [
                    block.text
                    for block in response.content
                    if hasattr(block, "text")
                ]
                content = "".join(text_parts)
                self._log_request(
                    start,
                    prompt_text,
                    response=content,
                    model=self.model,
                    stop_reason=response.stop_reason,
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                )
                return content
            except _anthropic.BadRequestError as exc:
                self._log_request(
                    start, prompt_text, error=str(exc), model=self.model
                )
                raise
            except retryable:
                raise
            except _anthropic.APIError as exc:
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
