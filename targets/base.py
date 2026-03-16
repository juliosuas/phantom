"""Base target abstract class for LLM provider adapters."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RequestLog:
    """Record of a single request/response exchange."""

    timestamp: float
    prompt: str
    response: str | None
    error: str | None
    latency_ms: float
    model: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class RateLimiter:
    """Token-bucket rate limiter for API calls."""

    def __init__(self, max_calls: int = 60, period_seconds: float = 60.0) -> None:
        self.max_calls = max_calls
        self.period_seconds = period_seconds
        self._call_timestamps: list[float] = []

    def wait_if_needed(self) -> None:
        """Block until a request slot is available."""
        now = time.monotonic()
        # Purge timestamps outside the current window.
        cutoff = now - self.period_seconds
        self._call_timestamps = [t for t in self._call_timestamps if t > cutoff]

        if len(self._call_timestamps) >= self.max_calls:
            sleep_for = self._call_timestamps[0] - cutoff
            if sleep_for > 0:
                logger.debug("Rate limit reached, sleeping %.2fs", sleep_for)
                time.sleep(sleep_for)

        self._call_timestamps.append(time.monotonic())


class BaseTarget(ABC):
    """Abstract base class for all LLM target adapters.

    Subclasses must implement the four abstract methods. The base class
    provides shared rate-limiting and request/response logging.
    """

    def __init__(
        self,
        *,
        rate_limit_calls: int = 60,
        rate_limit_period: float = 60.0,
        max_retries: int = 3,
        retry_base_delay: float = 1.0,
    ) -> None:
        self._rate_limiter = RateLimiter(
            max_calls=rate_limit_calls,
            period_seconds=rate_limit_period,
        )
        self.max_retries = max_retries
        self.retry_base_delay = retry_base_delay
        self._request_log: list[RequestLog] = []

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def send(self, prompt: str, **kwargs: Any) -> str:
        """Send a single user prompt and return the model response."""

    @abstractmethod
    def send_with_system(
        self, system_prompt: str, prompt: str, **kwargs: Any
    ) -> str:
        """Send a prompt with a system-level instruction."""

    @abstractmethod
    def send_multi_turn(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        """Send a multi-turn conversation and return the final response."""

    @abstractmethod
    def get_model_info(self) -> dict[str, Any]:
        """Return metadata about the underlying model."""

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _pre_request(self) -> float:
        """Rate-limit and return a start timestamp."""
        self._rate_limiter.wait_if_needed()
        return time.monotonic()

    def _log_request(
        self,
        start: float,
        prompt: str,
        response: str | None = None,
        error: str | None = None,
        model: str | None = None,
        **metadata: Any,
    ) -> None:
        elapsed_ms = (time.monotonic() - start) * 1000
        entry = RequestLog(
            timestamp=time.time(),
            prompt=prompt,
            response=response,
            error=error,
            latency_ms=round(elapsed_ms, 2),
            model=model,
            metadata=metadata,
        )
        self._request_log.append(entry)
        if error:
            logger.warning(
                "Request failed (%.0fms): %s", elapsed_ms, error
            )
        else:
            logger.debug("Request succeeded (%.0fms)", elapsed_ms)

    def _retry_with_backoff(
        self,
        func: Any,
        *args: Any,
        retryable_exceptions: tuple[type[BaseException], ...] = (Exception,),
        **kwargs: Any,
    ) -> Any:
        """Call *func* with exponential back-off on transient errors."""
        last_exc: BaseException | None = None
        for attempt in range(self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except retryable_exceptions as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    delay = self.retry_base_delay * (2 ** attempt)
                    logger.info(
                        "Retry %d/%d after %.1fs: %s",
                        attempt + 1,
                        self.max_retries,
                        delay,
                        exc,
                    )
                    time.sleep(delay)
        raise last_exc  # type: ignore[misc]

    @property
    def request_history(self) -> list[RequestLog]:
        """Return a copy of the request log."""
        return list(self._request_log)
