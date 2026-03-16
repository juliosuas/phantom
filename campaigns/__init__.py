"""Phantom Campaigns - Orchestrated LLM Red Teaming Campaigns.

Provides campaign management for organizing, executing, and tracking
sets of adversarial attacks against language models. Supports presets
for common assessment patterns and full lifecycle management.
"""

from campaigns.campaign import Campaign, CampaignManager
from campaigns.presets import CampaignPresets

__all__ = [
    "Campaign",
    "CampaignManager",
    "CampaignPresets",
]
