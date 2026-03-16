"""Attack delivery layer for Phantom.

The :class:`Attacker` wraps a target adapter and handles the mechanics of
sending adversarial prompts: rate-limiting, retries with exponential back-off,
timeout enforcement, and error tracking.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol


# ------------------------------------------------------------------
# Target protocol
# ------------------------------------------------------------------


class BaseTarget(Protocol):
    """Duck-typed interface that every target adapter must implement."""

    async def send(self, prompt: str, **kwargs: Any) -> str: ...

    async def send_multi_turn(self, messages: List[Dict[str, str]]) -> List[str]: ...


# ------------------------------------------------------------------
# Error tracking
# ------------------------------------------------------------------


@dataclass
class _ErrorRecord:
    """Internal bookkeeping for errors encountered during delivery."""

    total_errors: int = 0
    last_error: Optional[str] = None
    error_counts: Dict[str, int] = field(default_factory=dict)

    def record(self, exc: Exception) -> None:
        error_type = type(exc).__name__
        self.total_errors += 1
        self.last_error = str(exc)
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1


class Attacker:
    """Delivers adversarial prompts to a target model.

    Wraps a :class:`BaseTarget` with production-hardened delivery logic
    including concurrency-safe rate limiting, automatic retries with
    exponential back-off, and per-session error tracking.

    Args:
        target: A target adapter instance (or ``None`` for dry-run mode).
        max_retries: Maximum number of retry attempts per request.
        retry_base_delay: Initial back-off delay in seconds (doubles each
            retry).
        requests_per_minute: Soft rate-limit cap.  Set to ``0`` to disable.
        timeout: Per-request timeout in seconds.
    """

    def __init__(
        self,
        target: Optional[BaseTarget] = None,
        max_retries: int = 3,
        retry_base_delay: float = 1.0,
        requests_per_minute: int = 60,
        timeout: int = 30,
    ) -> None:
        self._target = target
        self._max_retries = max_retries
        self._retry_base_delay = retry_base_delay
        self._rpm_limit = requests_per_minute
        self._timeout = timeout
        self._errors = _ErrorRecord()
        self._request_timestamps: List[float] = []
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def send_attack(
        self,
        attack_prompt: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Send a single adversarial prompt to the target.

        Args:
            attack_prompt: The prompt payload to deliver.
            context: Optional metadata forwarded to the target adapter.

        Returns:
            The raw text response from the target model.

        Raises:
            RuntimeError: If no target adapter is configured.
            TimeoutError: If all attempts exceed the timeout.
            Exception: Re-raises the last exception after exhausting retries.
        """
        if self._target is None:
            raise RuntimeError(
                "No target configured. Provide a BaseTarget to the Attacker."
            )

        kwargs: Dict[str, Any] = {}
        if context:
            kwargs.update(context)

        return await self._send_with_retry(
            self._target.send, attack_prompt, **kwargs
        )

    async def send_multi_turn(
        self,
        messages: List[Dict[str, str]],
    ) -> List[str]:
        """Deliver a multi-turn conversation sequence.

        Args:
            messages: Ordered list of message dicts, each containing at
                minimum a ``role`` and ``content`` key.

        Returns:
            List of model responses, one per turn.

        Raises:
            RuntimeError: If no target adapter is configured.
        """
        if self._target is None:
            raise RuntimeError(
                "No target configured. Provide a BaseTarget to the Attacker."
            )

        await self._enforce_rate_limit()
        try:
            return await asyncio.wait_for(
                self._target.send_multi_turn(messages),
                timeout=self._timeout * len(messages),
            )
        except Exception as exc:
            self._errors.record(exc)
            raise

    async def send_with_system(
        self,
        system_prompt: str,
        attack: str,
    ) -> str:
        """Send an attack with a custom system prompt.

        This is a convenience wrapper that constructs the appropriate
        message sequence and delegates to :meth:`send_attack`.

        Args:
            system_prompt: The system-level instruction to set.
            attack: The adversarial user message.

        Returns:
            The raw text response from the target model.
        """
        return await self.send_attack(
            attack,
            context={"system_prompt": system_prompt},
        )

    @property
    def error_stats(self) -> Dict[str, Any]:
        """Return a snapshot of accumulated error statistics."""
        return {
            "total_errors": self._errors.total_errors,
            "last_error": self._errors.last_error,
            "error_counts": dict(self._errors.error_counts),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _send_with_retry(self, fn, *args, **kwargs) -> str:
        """Call *fn* with retries, exponential back-off, and rate limiting."""
        last_exc: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            await self._enforce_rate_limit()

            try:
                return await asyncio.wait_for(
                    fn(*args, **kwargs),
                    timeout=self._timeout,
                )
            except asyncio.TimeoutError:
                last_exc = TimeoutError(
                    f"Request timed out after {self._timeout}s "
                    f"(attempt {attempt + 1}/{self._max_retries + 1})"
                )
                self._errors.record(last_exc)
            except Exception as exc:
                last_exc = exc
                self._errors.record(exc)

            # Exponential back-off (skip after final attempt)
            if attempt < self._max_retries:
                delay = self._retry_base_delay * (2 ** attempt)
                await asyncio.sleep(delay)

        raise last_exc  # type: ignore[misc]

    async def _enforce_rate_limit(self) -> None:
        """Sleep if necessary to stay within the configured RPM limit."""
        if self._rpm_limit <= 0:
            return

        async with self._lock:
            now = time.monotonic()
            window_start = now - 60.0

            # Prune timestamps older than the sliding window
            self._request_timestamps = [
                ts for ts in self._request_timestamps if ts > window_start
            ]

            if len(self._request_timestamps) >= self._rpm_limit:
                oldest_in_window = self._request_timestamps[0]
                sleep_duration = 60.0 - (now - oldest_in_window)
                if sleep_duration > 0:
                    await asyncio.sleep(sleep_duration)

            self._request_timestamps.append(time.monotonic())
