"""
Attack Library - Central registry for all LLM red teaming attack techniques.

Provides loading, filtering, and searching across the full attack catalog,
with each attack mapped to the OWASP LLM Top 10.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Union

from .techniques.prompt_injection import PromptInjectionTechniques
from .techniques.jailbreak import JailbreakTechniques
from .techniques.extraction import ExtractionTechniques
from .techniques.encoding import EncodingTechniques
from .techniques.multilingual import MultilingualTechniques
from .techniques.roleplay import RoleplayTechniques


# ---------------------------------------------------------------------------
# OWASP LLM Top 10 mapping
# ---------------------------------------------------------------------------

OWASP_LLM_TOP_10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft",
}


# ---------------------------------------------------------------------------
# Attack dataclass
# ---------------------------------------------------------------------------

@dataclass
class Attack:
    """A single attack technique with metadata."""

    name: str
    category: str
    technique: str
    prompt: Union[str, List[str]]
    description: str
    severity: str  # "low", "medium", "high", "critical"
    owasp_category: str  # e.g. "LLM01"
    tags: List[str] = field(default_factory=list)
    mutation_compatible: bool = True

    @property
    def owasp_label(self) -> str:
        """Return the human-readable OWASP label for this attack."""
        return OWASP_LLM_TOP_10.get(self.owasp_category, "Unknown")

    def __repr__(self) -> str:
        return (
            f"Attack(name={self.name!r}, category={self.category!r}, "
            f"severity={self.severity!r}, owasp={self.owasp_category})"
        )


# ---------------------------------------------------------------------------
# AttackLibrary
# ---------------------------------------------------------------------------

class AttackLibrary:
    """Central registry that aggregates every technique module."""

    _technique_classes = [
        PromptInjectionTechniques,
        JailbreakTechniques,
        ExtractionTechniques,
        EncodingTechniques,
        MultilingualTechniques,
        RoleplayTechniques,
    ]

    def __init__(self) -> None:
        self._attacks: Optional[List[Attack]] = None

    # -- loading -----------------------------------------------------------

    def load_all(self) -> List[Attack]:
        """Load and return every attack from every technique module."""
        if self._attacks is None:
            self._attacks = []
            for cls in self._technique_classes:
                self._attacks.extend(cls.get_all())
        return list(self._attacks)

    # -- filtering ---------------------------------------------------------

    def get_by_category(self, category: str) -> List[Attack]:
        """Return attacks whose *category* matches (case-insensitive)."""
        cat = category.lower()
        return [a for a in self.load_all() if a.category.lower() == cat]

    def get_by_owasp(self, owasp_id: str) -> List[Attack]:
        """Return attacks mapped to a given OWASP LLM ID (e.g. 'LLM01')."""
        oid = owasp_id.upper()
        return [a for a in self.load_all() if a.owasp_category.upper() == oid]

    def get_by_severity(self, severity: str) -> List[Attack]:
        """Return attacks with the given severity level."""
        sev = severity.lower()
        return [a for a in self.load_all() if a.severity.lower() == sev]

    def search(self, query: str) -> List[Attack]:
        """Search attacks by name or description (case-insensitive substring)."""
        q = query.lower()
        return [
            a
            for a in self.load_all()
            if q in a.name.lower() or q in a.description.lower()
        ]

    # -- properties --------------------------------------------------------

    @property
    def total_count(self) -> int:
        """Total number of attacks in the library."""
        return len(self.load_all())
