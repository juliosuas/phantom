"""Tests for the attack library and technique modules."""

import pytest

from attacks.library import AttackLibrary, Attack, OWASP_LLM_TOP_10
from attacks.techniques.prompt_injection import PromptInjectionTechniques
from attacks.techniques.jailbreak import JailbreakTechniques
from attacks.techniques.extraction import ExtractionTechniques
from attacks.techniques.encoding import EncodingTechniques
from attacks.techniques.multilingual import MultilingualTechniques
from attacks.techniques.roleplay import RoleplayTechniques


class TestAttackDataclass:
    """Tests for the Attack dataclass."""

    def test_attack_creation(self):
        attack = Attack(
            name="Test Attack",
            category="test",
            technique="test_technique",
            prompt="Hello",
            description="A test attack.",
            severity="medium",
            owasp_category="LLM01",
        )
        assert attack.name == "Test Attack"
        assert attack.severity == "medium"
        assert attack.mutation_compatible is True

    def test_owasp_label(self):
        attack = Attack(
            name="Test",
            category="test",
            technique="test",
            prompt="Hello",
            description="Test",
            severity="low",
            owasp_category="LLM01",
        )
        assert attack.owasp_label == "Prompt Injection"

    def test_owasp_label_unknown(self):
        attack = Attack(
            name="Test",
            category="test",
            technique="test",
            prompt="Hello",
            description="Test",
            severity="low",
            owasp_category="LLM99",
        )
        assert attack.owasp_label == "Unknown"


class TestAttackLibrary:
    """Tests for the AttackLibrary."""

    def setup_method(self):
        self.library = AttackLibrary()

    def test_load_all_returns_attacks(self):
        attacks = self.library.load_all()
        assert len(attacks) > 0
        assert all(isinstance(a, Attack) for a in attacks)

    def test_total_count(self):
        assert self.library.total_count > 0

    def test_get_by_category(self):
        attacks = self.library.get_by_category("prompt_injection")
        assert len(attacks) > 0
        assert all(a.category == "prompt_injection" for a in attacks)

    def test_get_by_category_case_insensitive(self):
        lower = self.library.get_by_category("prompt_injection")
        upper = self.library.get_by_category("PROMPT_INJECTION")
        assert len(lower) == len(upper)

    def test_get_by_owasp(self):
        attacks = self.library.get_by_owasp("LLM01")
        assert len(attacks) > 0
        assert all(a.owasp_category == "LLM01" for a in attacks)

    def test_get_by_severity(self):
        attacks = self.library.get_by_severity("high")
        assert len(attacks) > 0
        assert all(a.severity == "high" for a in attacks)

    def test_search(self):
        results = self.library.search("DAN")
        assert len(results) > 0

    def test_search_no_results(self):
        results = self.library.search("xyznonexistent12345")
        assert len(results) == 0


class TestTechniqueModules:
    """Test that each technique module produces valid attacks."""

    @pytest.mark.parametrize(
        "cls",
        [
            PromptInjectionTechniques,
            JailbreakTechniques,
            ExtractionTechniques,
            EncodingTechniques,
            MultilingualTechniques,
            RoleplayTechniques,
        ],
    )
    def test_get_all_returns_attacks(self, cls):
        attacks = cls.get_all()
        assert len(attacks) > 0
        for a in attacks:
            assert isinstance(a, Attack)
            assert a.name
            assert a.category
            assert a.technique
            assert a.prompt
            assert a.description
            assert a.severity in ("low", "medium", "high", "critical")
            assert a.owasp_category.startswith("LLM")


class TestOwaspMapping:
    """Tests for the OWASP LLM Top 10 mapping."""

    def test_all_ten_categories_present(self):
        assert len(OWASP_LLM_TOP_10) == 10

    def test_ids_are_sequential(self):
        for i in range(1, 11):
            assert f"LLM{i:02d}" in OWASP_LLM_TOP_10
