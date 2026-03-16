"""Pre-built campaign presets for common red-teaming scenarios.

Each preset defines a self-contained configuration dictionary that the
:class:`~campaigns.campaign.CampaignManager` consumes when creating and
running a campaign.  Presets range from a fast smoke test to a full
OWASP LLM Top 10 compliance assessment.
"""

from __future__ import annotations

from typing import Any, Dict, List


class CampaignPresets:
    """Registry of built-in campaign preset configurations.

    Every preset is a dictionary with the following keys:

    - ``name`` -- canonical preset identifier.
    - ``description`` -- short human-readable summary.
    - ``categories`` -- attack category names to include.
    - ``max_attacks`` -- upper bound on the number of attacks to run.
    - ``mutation_rounds`` -- how many rounds of prompt mutation to apply
      to successful attacks.
    - ``timeout_minutes`` -- suggested wall-clock time limit.
    - ``include_multi_turn`` -- whether to include multi-turn attack
      sequences.
    """

    QUICK_SCAN: Dict[str, Any] = {
        "name": "QUICK_SCAN",
        "description": (
            "5-minute basic smoke test. Runs a small set of prompt injection "
            "and basic jailbreak attacks with no mutation to quickly surface "
            "obvious vulnerabilities."
        ),
        "categories": [
            "prompt_injection",
            "jailbreak_basic",
        ],
        "max_attacks": 15,
        "mutation_rounds": 0,
        "timeout_minutes": 5,
        "include_multi_turn": False,
    }

    STANDARD: Dict[str, Any] = {
        "name": "STANDARD",
        "description": (
            "30-minute thorough assessment. Covers injection, jailbreak, "
            "extraction, and encoding categories with a single round of "
            "mutation on successful attacks for balanced coverage."
        ),
        "categories": [
            "prompt_injection",
            "jailbreak",
            "extraction",
            "encoding",
        ],
        "max_attacks": 60,
        "mutation_rounds": 1,
        "timeout_minutes": 30,
        "include_multi_turn": False,
    }

    DEEP_DIVE: Dict[str, Any] = {
        "name": "DEEP_DIVE",
        "description": (
            "2+ hour comprehensive assessment. Exercises every attack "
            "category with three rounds of mutation and multi-turn attack "
            "sequences for maximum coverage and depth."
        ),
        "categories": [
            "prompt_injection",
            "jailbreak",
            "jailbreak_basic",
            "extraction",
            "encoding",
            "multilingual",
            "roleplay",
            "information_disclosure",
            "privilege_escalation",
            "denial_of_service",
            "data_exfiltration",
            "safety_bypass",
            "instruction_hierarchy",
        ],
        "max_attacks": None,  # no limit
        "mutation_rounds": 3,
        "timeout_minutes": 120,
        "include_multi_turn": True,
    }

    OWASP_LLM_TOP10: Dict[str, Any] = {
        "name": "OWASP_LLM_TOP10",
        "description": (
            "OWASP LLM Top 10 compliance check. Maps attacks to each of "
            "the ten OWASP categories, generates a compliance scorecard, "
            "and specifically tests prompt injection, insecure output "
            "handling, training data poisoning, denial of service, and "
            "supply-chain risks."
        ),
        "categories": [
            "prompt_injection",          # LLM01 - Prompt Injection
            "insecure_output",           # LLM02 - Insecure Output Handling
            "training_data_poisoning",   # LLM03 - Training Data Poisoning
            "denial_of_service",         # LLM04 - Model Denial of Service
            "supply_chain",              # LLM05 - Supply Chain Vulnerabilities
            "information_disclosure",    # LLM06 - Sensitive Information Disclosure
            "insecure_plugin",           # LLM07 - Insecure Plugin Design
            "excessive_agency",          # LLM08 - Excessive Agency
            "overreliance",              # LLM09 - Overreliance
            "model_theft",               # LLM10 - Model Theft
        ],
        "max_attacks": 100,
        "mutation_rounds": 2,
        "timeout_minutes": 60,
        "include_multi_turn": True,
        "owasp_mapping": {
            "LLM01": {"name": "Prompt Injection", "categories": ["prompt_injection"]},
            "LLM02": {"name": "Insecure Output Handling", "categories": ["insecure_output"]},
            "LLM03": {"name": "Training Data Poisoning", "categories": ["training_data_poisoning"]},
            "LLM04": {"name": "Model Denial of Service", "categories": ["denial_of_service"]},
            "LLM05": {"name": "Supply Chain Vulnerabilities", "categories": ["supply_chain"]},
            "LLM06": {"name": "Sensitive Information Disclosure", "categories": ["information_disclosure"]},
            "LLM07": {"name": "Insecure Plugin Design", "categories": ["insecure_plugin"]},
            "LLM08": {"name": "Excessive Agency", "categories": ["excessive_agency"]},
            "LLM09": {"name": "Overreliance", "categories": ["overreliance"]},
            "LLM10": {"name": "Model Theft", "categories": ["model_theft"]},
        },
    }

    # Registry of all presets by canonical name.
    _PRESETS: Dict[str, Dict[str, Any]] = {
        "QUICK_SCAN": QUICK_SCAN,
        "STANDARD": STANDARD,
        "DEEP_DIVE": DEEP_DIVE,
        "OWASP_LLM_TOP10": OWASP_LLM_TOP10,
    }

    @classmethod
    def get_preset(cls, name: str) -> Dict[str, Any]:
        """Look up a preset configuration by name.

        The lookup is case-insensitive; both ``"quick_scan"`` and
        ``"QUICK_SCAN"`` are accepted.

        Args:
            name: The preset identifier.

        Returns:
            A copy of the preset configuration dictionary.

        Raises:
            ValueError: If no preset with the given name exists.
        """
        key = name.upper()
        if key not in cls._PRESETS:
            available = ", ".join(sorted(cls._PRESETS.keys()))
            raise ValueError(
                f"Unknown preset '{name}'. Available presets: {available}"
            )
        # Return a shallow copy so callers cannot mutate the registry.
        return dict(cls._PRESETS[key])

    @classmethod
    def list_presets(cls) -> List[Dict[str, Any]]:
        """Return summary information for all available presets.

        Returns:
            A list of dictionaries, each containing ``name``,
            ``description``, ``categories``, ``max_attacks``,
            ``mutation_rounds``, ``timeout_minutes``, and
            ``include_multi_turn``.
        """
        return [
            {
                "name": p["name"],
                "description": p["description"],
                "categories": list(p["categories"]),
                "max_attacks": p["max_attacks"],
                "mutation_rounds": p["mutation_rounds"],
                "timeout_minutes": p["timeout_minutes"],
                "include_multi_turn": p["include_multi_turn"],
            }
            for p in cls._PRESETS.values()
        ]
