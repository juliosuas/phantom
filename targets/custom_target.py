"""Custom HTTP target adapter for arbitrary LLM endpoints."""

from __future__ import annotations

import base64
import logging
from typing import Any

import httpx

from targets.base import BaseTarget

logger = logging.getLogger(__name__)


class CustomTarget(BaseTarget):
    """Send prompts to any HTTP endpoint.

    This adapter is designed for proprietary or self-hosted LLM APIs whose
    request/response format can be described with simple field mappings.

    Parameters
    ----------
    url:
        Full URL of the endpoint (e.g. ``"https://api.example.com/v1/chat"``).
    headers:
        Extra HTTP headers added to every request.
    prompt_field:
        JSON key that carries the user prompt in the request body.
    response_field:
        JSON key (or dot-separated path) to extract the answer from the
        response body.  Nested paths like ``"choices.0.text"`` are supported.
    method:
        HTTP method (``"POST"`` or ``"GET"``).
    auth_type:
        One of ``"bearer"``, ``"api_key_header"``, ``"basic"``, or ``None``.
    auth_value:
        The token / key / ``"user:password"`` string for the chosen auth
        method.
    auth_header_name:
        Header name used when ``auth_type="api_key_header"``
        (default ``"X-API-Key"``).
    timeout:
        Request timeout in seconds.
    rate_limit_calls:
        Max requests per ``rate_limit_period`` seconds.
    rate_limit_period:
        Window length in seconds for rate limiting.
    max_retries:
        Number of retries on transient HTTP errors.
    """

    _RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        prompt_field: str = "message",
        response_field: str = "response",
        method: str = "POST",
        auth_type: str | None = None,
        auth_value: str | None = None,
        auth_header_name: str = "X-API-Key",
        timeout: float = 30.0,
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
        self.url = url
        self.prompt_field = prompt_field
        self.response_field = response_field
        self.method = method.upper()
        self.timeout = timeout

        # Build default headers with auth.
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if headers:
            self._headers.update(headers)

        self._apply_auth(auth_type, auth_value, auth_header_name)

        self._http = httpx.Client(
            headers=self._headers,
            timeout=httpx.Timeout(timeout),
        )

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    def _apply_auth(
        self,
        auth_type: str | None,
        auth_value: str | None,
        auth_header_name: str,
    ) -> None:
        if auth_type is None:
            return
        if not auth_value:
            raise ValueError(
                f"auth_value is required when auth_type={auth_type!r}"
            )

        auth_type = auth_type.lower()
        if auth_type == "bearer":
            self._headers["Authorization"] = f"Bearer {auth_value}"
        elif auth_type == "api_key_header":
            self._headers[auth_header_name] = auth_value
        elif auth_type == "basic":
            if ":" not in auth_value:
                raise ValueError(
                    "auth_value for basic auth must be 'username:password'"
                )
            encoded = base64.b64encode(auth_value.encode()).decode()
            self._headers["Authorization"] = f"Basic {encoded}"
        else:
            raise ValueError(
                f"Unsupported auth_type {auth_type!r}. "
                "Use 'bearer', 'api_key_header', or 'basic'."
            )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def send(self, prompt: str, **kwargs: Any) -> str:
        """Send a prompt as a simple JSON payload."""
        body = {self.prompt_field: prompt, **kwargs}
        return self._do_request(body, prompt)

    def send_with_system(
        self, system_prompt: str, prompt: str, **kwargs: Any
    ) -> str:
        """Send a prompt with a system instruction.

        The system prompt is placed in a ``system_prompt`` field alongside
        the main prompt field.
        """
        body = {
            self.prompt_field: prompt,
            "system_prompt": system_prompt,
            **kwargs,
        }
        return self._do_request(body, prompt)

    def send_multi_turn(
        self, messages: list[dict[str, str]], **kwargs: Any
    ) -> str:
        """Send a multi-turn conversation payload.

        Messages are sent under a ``messages`` key with the last user
        message also placed in the prompt field for endpoints that
        expect both.
        """
        last_user = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        body: dict[str, Any] = {
            "messages": messages,
            self.prompt_field: last_user,
            **kwargs,
        }
        return self._do_request(body, last_user)

    def get_model_info(self) -> dict[str, Any]:
        return {
            "provider": "custom",
            "url": self.url,
            "method": self.method,
            "prompt_field": self.prompt_field,
            "response_field": self.response_field,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_field(self, data: Any, path: str) -> str:
        """Walk a dot-separated path into a nested dict/list.

        ``"choices.0.text"`` would resolve ``data["choices"][0]["text"]``.
        """
        current = data
        for part in path.split("."):
            if isinstance(current, dict):
                current = current[part]
            elif isinstance(current, (list, tuple)):
                current = current[int(part)]
            else:
                raise KeyError(
                    f"Cannot traverse into {type(current).__name__} with key {part!r}"
                )
        return str(current)

    def _do_request(self, body: dict[str, Any], prompt_text: str) -> str:
        start = self._pre_request()

        def _execute() -> str:
            if self.method == "POST":
                resp = self._http.post(self.url, json=body)
            elif self.method == "GET":
                resp = self._http.get(self.url, params=body)  # type: ignore[arg-type]
            else:
                raise ValueError(f"Unsupported HTTP method: {self.method}")

            if resp.status_code in self._RETRYABLE_STATUS_CODES:
                resp.raise_for_status()  # triggers retry

            resp.raise_for_status()

            data = resp.json()
            content = self._extract_field(data, self.response_field)
            self._log_request(
                start,
                prompt_text,
                response=content,
                status_code=resp.status_code,
            )
            return content

        retryable = (httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException)

        try:
            return self._retry_with_backoff(
                _execute, retryable_exceptions=retryable
            )
        except retryable as exc:
            self._log_request(start, prompt_text, error=str(exc))
            raise
        except Exception as exc:
            self._log_request(start, prompt_text, error=str(exc))
            raise

    def __del__(self) -> None:
        try:
            self._http.close()
        except Exception:
            pass
