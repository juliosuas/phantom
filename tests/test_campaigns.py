"""Tests for the campaigns module."""

import os
import tempfile

import pytest

from campaigns.campaign import Campaign, CampaignManager, CampaignStatus
from campaigns.presets import CampaignPresets


class TestCampaignPresets:
    """Tests for campaign presets."""

    def test_list_presets(self):
        presets = CampaignPresets.list_presets()
        assert len(presets) >= 4
        names = [p["name"] for p in presets]
        assert "QUICK_SCAN" in names
        assert "STANDARD" in names
        assert "DEEP_DIVE" in names
        assert "OWASP_LLM_TOP10" in names

    def test_get_preset_case_insensitive(self):
        p1 = CampaignPresets.get_preset("quick_scan")
        p2 = CampaignPresets.get_preset("QUICK_SCAN")
        assert p1["name"] == p2["name"]

    def test_get_preset_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown preset"):
            CampaignPresets.get_preset("nonexistent")

    def test_preset_has_required_keys(self):
        for preset in CampaignPresets.list_presets():
            assert "name" in preset
            assert "description" in preset
            assert "categories" in preset
            assert "mutation_rounds" in preset
            assert isinstance(preset["categories"], list)

    def test_get_preset_returns_copy(self):
        p1 = CampaignPresets.get_preset("STANDARD")
        p1["categories"].append("custom")
        p2 = CampaignPresets.get_preset("STANDARD")
        assert "custom" not in p2["categories"]


class TestCampaignDataclass:
    """Tests for the Campaign dataclass."""

    def test_campaign_creation(self):
        campaign = Campaign(id="test123", name="Test Campaign")
        assert campaign.id == "test123"
        assert campaign.name == "Test Campaign"
        assert campaign.status == CampaignStatus.PENDING
        assert campaign.results == []

    def test_campaign_status_enum(self):
        assert CampaignStatus.PENDING.value == "pending"
        assert CampaignStatus.RUNNING.value == "running"
        assert CampaignStatus.COMPLETED.value == "completed"
        assert CampaignStatus.FAILED.value == "failed"


class TestCampaignManager:
    """Tests for the CampaignManager."""

    def setup_method(self):
        self._tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmpfile.close()
        self.manager = CampaignManager(db_path=self._tmpfile.name)

    def teardown_method(self):
        try:
            os.unlink(self._tmpfile.name)
        except OSError:
            pass

    def test_create_campaign(self):
        campaign = self.manager.create(
            name="Test Campaign",
            target_config={"target_type": "openai", "target_model": "gpt-4"},
        )
        assert campaign.name == "Test Campaign"
        assert campaign.status == CampaignStatus.PENDING
        assert campaign.id

    def test_get_campaign(self):
        created = self.manager.create(
            name="Retrieval Test",
            target_config={"target_type": "openai"},
        )
        fetched = self.manager.get(created.id)
        assert fetched.name == "Retrieval Test"
        assert fetched.id == created.id

    def test_get_nonexistent_raises(self):
        with pytest.raises(KeyError):
            self.manager.get("nonexistent_id")

    def test_list_all(self):
        self.manager.create(
            name="Campaign A",
            target_config={"target_type": "openai"},
        )
        self.manager.create(
            name="Campaign B",
            target_config={"target_type": "anthropic"},
        )
        campaigns = self.manager.list_all()
        assert len(campaigns) >= 2
        names = [c["name"] for c in campaigns]
        assert "Campaign A" in names
        assert "Campaign B" in names

    def test_delete_campaign(self):
        created = self.manager.create(
            name="To Delete",
            target_config={"target_type": "openai"},
        )
        self.manager.delete(created.id)
        with pytest.raises(KeyError):
            self.manager.get(created.id)

    def test_create_with_preset(self):
        campaign = self.manager.create(
            name="Preset Test",
            target_config={"target_type": "openai"},
            preset="QUICK_SCAN",
        )
        assert campaign.preset_name == "QUICK_SCAN"

    def test_get_summary_empty_campaign(self):
        campaign = self.manager.create(
            name="Empty Campaign",
            target_config={"target_type": "openai"},
        )
        summary = self.manager.get_summary(campaign.id)
        assert summary["total"] == 0
        assert summary["succeeded"] == 0
