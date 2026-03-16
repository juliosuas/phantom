"""Phantom Backend - Flask API server and database layer.

Provides the REST API and SQLite persistence for the Phantom LLM Red
Teaming platform, powering the web dashboard and programmatic access.
"""

from backend.db import (
    init_db,
    save_campaign,
    get_campaign,
    list_campaigns,
    update_campaign_status,
    delete_campaign,
    save_result,
    get_results,
    get_summary,
)

__all__ = [
    "init_db",
    "save_campaign",
    "get_campaign",
    "list_campaigns",
    "update_campaign_status",
    "delete_campaign",
    "save_result",
    "get_results",
    "get_summary",
]
