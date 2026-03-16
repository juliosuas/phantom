"""Local LLM target adapter for Ollama, llama.cpp, and OpenAI-compatible servers."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from targets.base import BaseTarget

logger = logging.getLogger(__name__)


class LocalTarget(BaseTarget):
    """Send prompts to a locally-running LLM server.

    Supported backends:

    * ``"ollama"`` -- Ollama REST API (default).
    * ``"llamacpp"`` -- llama.cpp ``server`` (``/completion`` endpoint).
    * ``"openai"`` -- Any server exposing an OpenAI-compatible
      ``/v1/chat/completions`` endpoint.

    Parameters
    ----------
    url:
        Base URL of the local server.
    model:
        Model name (interpreted by the backend).
    backend:
        One of ``"ollama"``, ``"llamacpp"``, or ``"openai"``.
    temperature:
        Sampling temperature.
    max_tokens:
        Maximum tokens in the response.
    timeout:
        Request timeout in seconds (local models can be slow).
    rate_limit_calls:
        Max requests per ``rate_limit_period`` seconds.
    rate_limit_period:
        Window length in seconds for rate limiting.
    max_retries:
        Number of retries on transient errors.
    """

    _VALID_BACKENDS = frozenset({"ollama", "llamacpp", "openai"})

    def __init__(
        self,
        url: str = "http://localhost:11434",
        model: str = "llama2",
        backend: str = "ollama",
        temperature: float = 0.7,
        max_tokens: int = 1024,
        timeout: float = 120.0,
        *,
        rate_limit_calls: int = 120,
        rate_limit_period: float = 60.0,
        max_retries: int = 2,
    ) -> None:
        super().__init__(
            rate_limit_calls=rate_limit_calls,
            rate_limit_period=rate_limit_period,
            max_retries=max_retries,
        )
        backend = backend.lower()
        if backend not in self._VALID_BACKENDS:
            raise ValueError(
                f"Unknown backend {backend!r}. "
                f"Supported: {', '.join(sorted(self._VALID_BACKENDS))}"
            )

        self.url = url.rstrip("/")
        self.model = model
        self.backend = backend
        self.temperature = temperature
        self.max_tokens = max_tokens

        self._http = httpx.Client(timeout=httpx.Timeout(timeout))

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def send(self, prompt: str, **kwargs: Any) -> str:
        return self._dispatch(prompt=prompt, system_prompt=None, **kwargs)

    def send_with_system(
        self, system_prompt: str, prompt: str, **kwargs: Any
    ) -> str:
        return self._dispatch(
            prompt=prompt, system_prompt=system_prompt, **kwargs
        )

    def send_multi_turn(
        self, messages: list[dict[str, str]], **kwargs: Any
    ) -> str:
        system_prompt: str | None = None
        conversation = list(messages)
        if conversation and conversation[0].get("role") == "system":
            system_prompt = conversation.pop(0).get("content")

        if self.backend in ("ollama", "openai"):
            return self._chat_api(
                conversation, system_prompt=system_prompt, **kwargs
            )

        # llama.cpp /completion doesn't have native multi-turn; flatten.
        combined = ""
        if system_prompt:
            combined += f"System: {system_prompt}\n"
        for msg in conversation:
            role = msg.get("role", "user").capitalize()
            combined += f"{role}: {msg.get('content', '')}\n"
        combined += "Assistant:"
        return self._dispatch(prompt=combined, system_prompt=None, **kwargs)

    def get_model_info(self) -> dict[str, Any]:
        return {
            "provider": "local",
            "backend": self.backend,
            "model": self.model,
            "url": self.url,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

    def health_check(self) -> dict[str, Any]:
        """Verify the local server is reachable and return basic info.

        Returns a dict with at least ``{"healthy": bool}``.
        """
        try:
            if self.backend == "ollama":
                resp = self._http.get(f"{self.url}/api/tags")
                resp.raise_for_status()
                data = resp.json()
                models = [m.get("name") for m in data.get("models", [])]
                return {"healthy": True, "models": models}

            if self.backend == "llamacpp":
                resp = self._http.get(f"{self.url}/health")
                resp.raise_for_status()
                return {"healthy": True, **resp.json()}

            if self.backend == "openai":
                resp = self._http.get(f"{self.url}/v1/models")
                resp.raise_for_status()
                data = resp.json()
                models = [m.get("id") for m in data.get("data", [])]
                return {"healthy": True, "models": models}

        except (httpx.HTTPError, Exception) as exc:
            logger.warning("Health check failed: %s", exc)
            return {"healthy": False, "error": str(exc)}

        return {"healthy": False, "error": "Unknown backend"}

    # ------------------------------------------------------------------
    # Backend dispatchers
    # ------------------------------------------------------------------

    def _dispatch(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> str:
        if self.backend == "ollama":
            return self._ollama_generate(prompt, system_prompt, **kwargs)
        if self.backend == "llamacpp":
            return self._llamacpp_completion(prompt, system_prompt, **kwargs)
        if self.backend == "openai":
            messages: list[dict[str, str]] = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            return self._chat_api(messages, system_prompt=None, **kwargs)
        raise ValueError(f"Unknown backend: {self.backend}")

    # ------------------------------------------------------------------
    # Ollama
    # ------------------------------------------------------------------

    def _ollama_generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> str:
        start = self._pre_request()
        url = f"{self.url}/api/generate"
        body: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": kwargs.pop("temperature", self.temperature),
                "num_predict": kwargs.pop("max_tokens", self.max_tokens),
            },
        }
        if system_prompt:
            body["system"] = system_prompt
        body.update(kwargs)

        return self._post(url, body, prompt, start)

    # ------------------------------------------------------------------
    # Ollama / OpenAI-compatible chat
    # ------------------------------------------------------------------

    def _chat_api(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> str:
        start = self._pre_request()
        prompt_text = messages[-1].get("content", "") if messages else ""

        full_messages = list(messages)
        if system_prompt:
            full_messages.insert(0, {"role": "system", "content": system_prompt})

        if self.backend == "ollama":
            url = f"{self.url}/api/chat"
            body: dict[str, Any] = {
                "model": self.model,
                "messages": full_messages,
                "stream": False,
                "options": {
                    "temperature": kwargs.pop("temperature", self.temperature),
                    "num_predict": kwargs.pop("max_tokens", self.max_tokens),
                },
            }
        else:
            # OpenAI-compatible
            url = f"{self.url}/v1/chat/completions"
            body = {
                "model": self.model,
                "messages": full_messages,
                "temperature": kwargs.pop("temperature", self.temperature),
                "max_tokens": kwargs.pop("max_tokens", self.max_tokens),
            }
        body.update(kwargs)

        return self._post(url, body, prompt_text, start)

    # ------------------------------------------------------------------
    # llama.cpp
    # ------------------------------------------------------------------

    def _llamacpp_completion(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> str:
        start = self._pre_request()
        url = f"{self.url}/completion"

        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"

        body: dict[str, Any] = {
            "prompt": full_prompt,
            "temperature": kwargs.pop("temperature", self.temperature),
            "n_predict": kwargs.pop("max_tokens", self.max_tokens),
            "stream": False,
        }
        body.update(kwargs)

        return self._post(url, body, prompt, start)

    # ------------------------------------------------------------------
    # Shared HTTP helper
    # ------------------------------------------------------------------

    def _post(
        self,
        url: str,
        body: dict[str, Any],
        prompt_text: str,
        start: float,
    ) -> str:
        retryable = (httpx.ConnectError, httpx.TimeoutException)

        def _execute() -> str:
            resp = self._http.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()

            # Extract response text based on backend format.
            if self.backend == "ollama":
                if "message" in data:
                    content = data["message"].get("content", "")
                else:
                    content = data.get("response", "")
            elif self.backend == "llamacpp":
                content = data.get("content", "")
            else:
                # OpenAI-compatible
                choices = data.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content", "")
                else:
                    content = ""

            self._log_request(
                start,
                prompt_text,
                response=content,
                model=self.model,
            )
            return content

        try:
            return self._retry_with_backoff(
                _execute, retryable_exceptions=retryable
            )
        except (httpx.HTTPStatusError, *retryable) as exc:
            self._log_request(
                start, prompt_text, error=str(exc), model=self.model
            )
            raise

    def __del__(self) -> None:
        try:
            self._http.close()
        except Exception:
            pass
