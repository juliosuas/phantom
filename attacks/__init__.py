"""
Phantom Attack Library - LLM Red Teaming Attack Techniques

Provides a comprehensive library of attack techniques for testing LLM safety,
organized by category and mapped to the OWASP LLM Top 10.
"""

from .library import AttackLibrary, Attack

# Technique sub-modules are imported lazily via AttackLibrary.load_all()
# to avoid circular imports (techniques import Attack from library).
from .techniques import prompt_injection  # noqa: F401
from .techniques import jailbreak  # noqa: F401
from .techniques import extraction  # noqa: F401
from .techniques import encoding  # noqa: F401
from .techniques import multilingual  # noqa: F401
from .techniques import roleplay  # noqa: F401

__all__ = [
    "AttackLibrary",
    "Attack",
    "prompt_injection",
    "jailbreak",
    "extraction",
    "encoding",
    "multilingual",
    "roleplay",
]
