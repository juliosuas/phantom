"""Phantom Core - LLM Red Teaming Engine.

The core engine for Phantom, an LLM red teaming platform that orchestrates
adversarial attacks against language models to identify vulnerabilities,
safety bypasses, and behavioral deviations.
"""

from core.config import PhantomConfig
from core.engine import PhantomEngine
from core.attacker import Attacker
from core.evaluator import Evaluator
from core.mutator import Mutator
from core.reporter import Reporter

__all__ = [
    "PhantomEngine",
    "Attacker",
    "Evaluator",
    "Mutator",
    "Reporter",
    "PhantomConfig",
]
