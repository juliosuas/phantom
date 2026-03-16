"""Tests for core.config.PhantomConfig."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from core.config import PhantomConfig


class TestPhantomConfigDefaults:
    """Tests for default configuration values."""

    def test_default_values(self):
        cfg = PhantomConfig()
        assert cfg.target_type == "openai"
        assert cfg.target_model == "gpt-4"
        assert cfg.max_concurrent == 5
        assert cfg.timeout == 30
        assert cfg.mutation_rounds == 3
        assert cfg.report_format == "html"
        assert cfg.db_path == "phantom.db"

    def test_categories_default_not_shared(self):
        cfg1 = PhantomConfig()
        cfg2 = PhantomConfig()
        cfg1.categories.append("custom_category")
        assert "custom_category" not in cfg2.categories


class TestPhantomConfigValidation:
    """Tests for the validate() method."""

    def test_valid_openai_config(self):
        cfg = PhantomConfig(target_type="openai", api_key="sk-test")
        errors = cfg.validate()
        assert errors == []

    def test_valid_anthropic_config(self):
        cfg = PhantomConfig(target_type="anthropic", api_key="sk-ant-test")
        errors = cfg.validate()
        assert errors == []

    def test_missing_api_key(self):
        cfg = PhantomConfig(target_type="openai", api_key=None)
        errors = cfg.validate()
        assert any("api_key" in e for e in errors)

    def test_custom_target_requires_url(self):
        cfg = PhantomConfig(target_type="custom", target_url=None)
        errors = cfg.validate()
        assert any("target_url" in e for e in errors)

    def test_invalid_target_type(self):
        cfg = PhantomConfig(target_type="invalid")
        errors = cfg.validate()
        assert any("target_type" in e for e in errors)

    def test_invalid_max_concurrent(self):
        cfg = PhantomConfig(
            target_type="openai", api_key="sk-test", max_concurrent=0
        )
        errors = cfg.validate()
        assert any("max_concurrent" in e for e in errors)

    def test_invalid_timeout(self):
        cfg = PhantomConfig(
            target_type="openai", api_key="sk-test", timeout=0
        )
        errors = cfg.validate()
        assert any("timeout" in e for e in errors)

    def test_invalid_report_format(self):
        cfg = PhantomConfig(
            target_type="openai", api_key="sk-test", report_format="pdf"
        )
        errors = cfg.validate()
        assert any("report_format" in e for e in errors)


class TestPhantomConfigFromYaml:
    """Tests for loading config from YAML files."""

    def test_from_yaml(self, tmp_path):
        yaml_content = {
            "target": {
                "type": "anthropic",
                "model": "claude-3",
            },
            "max_concurrent": 10,
            "timeout": 60,
        }
        yaml_file = tmp_path / "phantom.yaml"
        yaml_file.write_text(yaml.dump(yaml_content))

        cfg = PhantomConfig.from_yaml(str(yaml_file))
        assert cfg.target_type == "anthropic"
        assert cfg.target_model == "claude-3"
        assert cfg.max_concurrent == 10
        assert cfg.timeout == 60

    def test_from_yaml_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            PhantomConfig.from_yaml("/nonexistent/phantom.yaml")


class TestPhantomConfigFromEnv:
    """Tests for loading config from environment variables."""

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_TARGET_TYPE", "anthropic")
        monkeypatch.setenv("PHANTOM_TARGET_MODEL", "claude-3")
        monkeypatch.setenv("PHANTOM_MAX_CONCURRENT", "10")
        monkeypatch.setenv("PHANTOM_CATEGORIES", "jailbreak,extraction")

        cfg = PhantomConfig.from_env()
        assert cfg.target_type == "anthropic"
        assert cfg.target_model == "claude-3"
        assert cfg.max_concurrent == 10
        assert cfg.categories == ["jailbreak", "extraction"]
