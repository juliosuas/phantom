"""Configuration management for Phantom.

Handles loading, validation, and merging of configuration from multiple
sources: dataclass defaults, YAML files, and environment variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


_DEFAULT_CATEGORIES = [
    "prompt_injection",
    "jailbreak",
    "information_disclosure",
    "privilege_escalation",
    "denial_of_service",
    "data_exfiltration",
    "safety_bypass",
    "instruction_hierarchy",
]

_ENV_PREFIX = "PHANTOM_"


@dataclass
class PhantomConfig:
    """Central configuration for a Phantom red-teaming session.

    Configuration is resolved in priority order (highest wins):
        1. Explicit constructor arguments
        2. Environment variables (prefixed ``PHANTOM_``)
        3. YAML config file
        4. Dataclass defaults

    Attributes:
        target_type: Backend provider type. One of ``openai``, ``anthropic``,
            ``custom``, or ``local``.
        target_model: Model identifier to target (e.g. ``gpt-4``).
        target_url: Optional endpoint URL for custom / local targets.
        api_key: API key for the target provider.
        max_concurrent: Maximum number of concurrent attack requests.
        timeout: Per-request timeout in seconds.
        mutation_rounds: How many rounds of mutation to apply to failed attacks.
        categories: Which attack categories to include in a campaign.
        report_format: Output report format (``html``, ``json``, ``markdown``).
        db_path: Path to the SQLite database for result persistence.
    """

    target_type: str = "openai"
    target_model: str = "gpt-4"
    target_url: Optional[str] = None
    api_key: Optional[str] = None
    max_concurrent: int = 5
    timeout: int = 30
    mutation_rounds: int = 3
    categories: List[str] = field(default_factory=lambda: list(_DEFAULT_CATEGORIES))
    report_format: str = "html"
    db_path: str = "phantom.db"

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PhantomConfig":
        """Create a config by loading a YAML file, then overlaying env vars.

        Args:
            path: Filesystem path to a YAML configuration file.

        Returns:
            A fully resolved ``PhantomConfig`` instance.

        Raises:
            FileNotFoundError: If *path* does not exist.
            yaml.YAMLError: If the file contains invalid YAML.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path, "r", encoding="utf-8") as fh:
            raw: Dict[str, Any] = yaml.safe_load(fh) or {}

        # Flatten nested keys (e.g. target.type -> target_type)
        flat = cls._flatten_yaml(raw)

        # Overlay environment variables
        flat = cls._overlay_env(flat)

        return cls(**{k: v for k, v in flat.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_env(cls) -> "PhantomConfig":
        """Create a config purely from environment variables.

        Environment variables are expected in the form ``PHANTOM_<FIELD>``
        (upper-case, underscore-separated).  For example:
        ``PHANTOM_TARGET_TYPE=anthropic``.

        Returns:
            A ``PhantomConfig`` instance populated from the environment.
        """
        return cls(**cls._overlay_env({}))

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> List[str]:
        """Validate the current configuration and return a list of errors.

        Returns:
            A list of human-readable error strings.  Empty if valid.
        """
        errors: List[str] = []

        valid_types = {"openai", "anthropic", "custom", "local"}
        if self.target_type not in valid_types:
            errors.append(
                f"target_type must be one of {valid_types}, got '{self.target_type}'"
            )

        if not self.target_model:
            errors.append("target_model must not be empty")

        if self.target_type in {"openai", "anthropic"} and not self.api_key:
            errors.append(f"api_key is required for target_type '{self.target_type}'")

        if self.target_type == "custom" and not self.target_url:
            errors.append("target_url is required for target_type 'custom'")

        if self.max_concurrent < 1:
            errors.append("max_concurrent must be >= 1")

        if self.timeout < 1:
            errors.append("timeout must be >= 1")

        if self.mutation_rounds < 0:
            errors.append("mutation_rounds must be >= 0")

        valid_formats = {"html", "json", "markdown"}
        if self.report_format not in valid_formats:
            errors.append(
                f"report_format must be one of {valid_formats}, "
                f"got '{self.report_format}'"
            )

        return errors

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _flatten_yaml(raw: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten a potentially nested YAML dict into config field names."""
        flat: Dict[str, Any] = {}
        for key, value in raw.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    flat[f"{key}_{sub_key}"] = sub_value
            else:
                flat[key] = value
        return flat

    @classmethod
    def _overlay_env(cls, base: Dict[str, Any]) -> Dict[str, Any]:
        """Overlay matching ``PHANTOM_*`` environment variables onto *base*.

        Handles type coercion for int and list fields based on the dataclass
        field annotations.
        """
        merged = dict(base)

        int_fields = {"max_concurrent", "timeout", "mutation_rounds"}
        list_fields = {"categories"}

        for field_name in cls.__dataclass_fields__:
            env_key = f"{_ENV_PREFIX}{field_name.upper()}"
            env_val = os.environ.get(env_key)
            if env_val is None:
                continue

            if field_name in int_fields:
                try:
                    merged[field_name] = int(env_val)
                except ValueError:
                    pass  # skip unparseable ints
            elif field_name in list_fields:
                merged[field_name] = [
                    item.strip() for item in env_val.split(",") if item.strip()
                ]
            else:
                merged[field_name] = env_val

        return merged
