"""Target adapters for sending attacks to LLM providers.

Usage::

    from targets import get_target

    config = SimpleNamespace(target_type="openai", model="gpt-4", api_key="sk-...")
    target = get_target(config)
    response = target.send("Hello, world!")
"""

from __future__ import annotations

from typing import Any

from targets.anthropic_target import AnthropicTarget
from targets.base import BaseTarget, RequestLog
from targets.custom_target import CustomTarget
from targets.local_target import LocalTarget
from targets.openai_target import OpenAITarget

__all__ = [
    "AnthropicTarget",
    "BaseTarget",
    "CustomTarget",
    "LocalTarget",
    "OpenAITarget",
    "RequestLog",
    "get_target",
]


def get_target(config: Any) -> BaseTarget:
    """Instantiate the appropriate target adapter from a configuration object.

    The *config* object must have a ``target_type`` attribute (or key) set to
    one of ``"openai"``, ``"anthropic"``, ``"custom"``, or ``"local"``.
    Additional attributes are forwarded as keyword arguments to the
    corresponding target class.

    Supported config attributes per target type
    --------------------------------------------

    **openai**: ``model``, ``api_key``, ``base_url``, ``temperature``,
    ``max_tokens``

    **anthropic**: ``model``, ``api_key``, ``temperature``, ``max_tokens``

    **custom**: ``url``, ``headers``, ``prompt_field``, ``response_field``,
    ``method``, ``auth_type``, ``auth_value``, ``auth_header_name``,
    ``timeout``

    **local**: ``url``, ``model``, ``backend``, ``temperature``,
    ``max_tokens``, ``timeout``
    """
    # Support both object attributes and dict-style configs.
    def _get(key: str, default: Any = None) -> Any:
        if isinstance(config, dict):
            return config.get(key, default)
        return getattr(config, key, default)

    target_type = _get("target_type")
    if target_type is None:
        raise ValueError(
            "config must have a 'target_type' attribute "
            "(one of 'openai', 'anthropic', 'custom', 'local')."
        )

    target_type = str(target_type).lower()

    # Shared rate-limit / retry kwargs.
    common_kwargs: dict[str, Any] = {}
    for key in ("rate_limit_calls", "rate_limit_period", "max_retries"):
        val = _get(key)
        if val is not None:
            common_kwargs[key] = val

    if target_type == "openai":
        return OpenAITarget(
            model=_get("model", "gpt-4"),
            api_key=_get("api_key"),
            base_url=_get("base_url"),
            temperature=_get("temperature", 0.7),
            max_tokens=_get("max_tokens", 1024),
            **common_kwargs,
        )

    if target_type == "anthropic":
        return AnthropicTarget(
            model=_get("model", "claude-sonnet-4-20250514"),
            api_key=_get("api_key"),
            temperature=_get("temperature", 0.7),
            max_tokens=_get("max_tokens", 1024),
            **common_kwargs,
        )

    if target_type == "custom":
        url = _get("url")
        if not url:
            raise ValueError("'url' is required for custom target type.")
        return CustomTarget(
            url=url,
            headers=_get("headers"),
            prompt_field=_get("prompt_field", "message"),
            response_field=_get("response_field", "response"),
            method=_get("method", "POST"),
            auth_type=_get("auth_type"),
            auth_value=_get("auth_value"),
            auth_header_name=_get("auth_header_name", "X-API-Key"),
            timeout=_get("timeout", 30.0),
            **common_kwargs,
        )

    if target_type == "local":
        return LocalTarget(
            url=_get("url", "http://localhost:11434"),
            model=_get("model", "llama2"),
            backend=_get("backend", "ollama"),
            temperature=_get("temperature", 0.7),
            max_tokens=_get("max_tokens", 1024),
            timeout=_get("timeout", 120.0),
            **common_kwargs,
        )

    raise ValueError(
        f"Unknown target_type {target_type!r}. "
        "Supported: 'openai', 'anthropic', 'custom', 'local'."
    )
