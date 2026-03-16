"""Flask API server for the Phantom LLM Red Teaming platform.

Serves the web dashboard and exposes a JSON REST API for managing
campaigns, browsing attacks, and generating reports.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from backend import db
from attacks.library import AttackLibrary, Attack, OWASP_LLM_TOP_10

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_UI_DIR = _PROJECT_ROOT / "ui"
_DEFAULT_PORT = 8666


def create_app(db_path: str | None = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        db_path: Override path for the SQLite database.  Defaults to
            ``phantom.db`` in the project root.

    Returns:
        A fully configured :class:`Flask` application instance.
    """
    app = Flask(__name__, static_folder=None)
    CORS(app)

    resolved_db = db_path or os.environ.get(
        "PHANTOM_DB_PATH", str(_PROJECT_ROOT / "phantom.db")
    )
    app.config["DB_PATH"] = resolved_db

    # Ensure tables exist.
    db.init_db(resolved_db)

    # Lazily loaded attack library (singleton per app).
    _library = AttackLibrary()

    # ------------------------------------------------------------------
    # Error handlers
    # ------------------------------------------------------------------

    @app.errorhandler(400)
    def bad_request(exc: Any) -> tuple:
        return jsonify({"error": "Bad request", "detail": str(exc)}), 400

    @app.errorhandler(404)
    def not_found(exc: Any) -> tuple:
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(exc: Any) -> tuple:
        logger.exception("Internal server error")
        return jsonify({"error": "Internal server error"}), 500

    # ------------------------------------------------------------------
    # Dashboard (serves static HTML from ui/)
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        """Serve the main dashboard page."""
        dashboard = _UI_DIR / "dashboard.html"
        if dashboard.exists():
            return send_from_directory(str(_UI_DIR), "dashboard.html")
        return jsonify({
            "message": "Phantom API is running. Dashboard not found at ui/dashboard.html.",
        })

    @app.route("/ui/<path:filename>")
    def serve_ui(filename: str):
        """Serve additional static assets from the ui/ directory."""
        return send_from_directory(str(_UI_DIR), filename)

    # ------------------------------------------------------------------
    # Campaign routes
    # ------------------------------------------------------------------

    @app.route("/api/campaigns", methods=["GET"])
    def list_campaigns():
        """Return all campaigns."""
        campaigns = db.list_campaigns(resolved_db)
        return jsonify({"campaigns": campaigns})

    @app.route("/api/campaigns", methods=["POST"])
    def create_campaign():
        """Create a new campaign from a JSON body.

        Expected body keys: ``name`` (required), ``target`` (optional,
        e.g. ``"openai:gpt-4"``), ``preset`` (optional).
        """
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400

        name = data.get("name")
        if not name:
            return jsonify({"error": "Field 'name' is required"}), 400

        # Parse target string like "openai:gpt-4"
        target_str = data.get("target", "openai:gpt-4")
        parts = target_str.split(":", 1) if isinstance(target_str, str) else ["openai", "gpt-4"]
        target_type = parts[0] if parts else "openai"
        target_model = parts[1] if len(parts) > 1 else "gpt-4"

        campaign = {
            "name": name,
            "description": data.get("description", ""),
            "target_type": target_type,
            "target_model": target_model,
            "target_url": data.get("target_url"),
            "preset": data.get("preset", "standard"),
            "status": "pending",
        }

        campaign_id = db.save_campaign(campaign, resolved_db)
        saved = db.get_campaign(campaign_id, resolved_db)
        return jsonify({"campaign": saved}), 201

    @app.route("/api/campaigns/<int:campaign_id>", methods=["GET"])
    def get_campaign(campaign_id: int):
        """Return a single campaign by ID."""
        campaign = db.get_campaign(campaign_id, resolved_db)
        if not campaign:
            return jsonify({"error": "Campaign not found"}), 404
        return jsonify({"campaign": campaign})

    @app.route("/api/campaigns/<int:campaign_id>/run", methods=["POST"])
    def run_campaign(campaign_id: int):
        """Mark a campaign as running.

        In a production deployment this would launch the async engine.
        Here it updates the status so the dashboard can reflect progress.
        """
        campaign = db.get_campaign(campaign_id, resolved_db)
        if not campaign:
            return jsonify({"error": "Campaign not found"}), 404

        if campaign["status"] == "running":
            return jsonify({"error": "Campaign is already running"}), 409

        db.update_campaign_status(campaign_id, "running", resolved_db)
        updated = db.get_campaign(campaign_id, resolved_db)
        return jsonify({"campaign": updated, "message": "Campaign started"})

    @app.route("/api/campaigns/<int:campaign_id>", methods=["DELETE"])
    def delete_campaign(campaign_id: int):
        """Delete a campaign and all its results."""
        deleted = db.delete_campaign(campaign_id, resolved_db)
        if not deleted:
            return jsonify({"error": "Campaign not found"}), 404
        return jsonify({"message": "Campaign deleted", "id": campaign_id})

    @app.route("/api/campaigns/<int:campaign_id>/results", methods=["GET"])
    def get_results(campaign_id: int):
        """Return attack results for a campaign."""
        campaign = db.get_campaign(campaign_id, resolved_db)
        if not campaign:
            return jsonify({"error": "Campaign not found"}), 404

        results = db.get_results(campaign_id, resolved_db)
        return jsonify({"campaign_id": campaign_id, "results": results})

    @app.route("/api/campaigns/<int:campaign_id>/summary", methods=["GET"])
    def get_summary(campaign_id: int):
        """Return summary statistics for a campaign."""
        campaign = db.get_campaign(campaign_id, resolved_db)
        if not campaign:
            return jsonify({"error": "Campaign not found"}), 404

        summary = db.get_summary(campaign_id, resolved_db)
        return jsonify({"campaign_id": campaign_id, "summary": summary})

    # ------------------------------------------------------------------
    # Attack library routes
    # ------------------------------------------------------------------

    @app.route("/api/attacks", methods=["GET"])
    def list_attacks():
        """Return all available attacks, with optional ``?category=`` filter."""
        category = request.args.get("category")
        if category:
            attacks = _library.get_by_category(category)
        else:
            attacks = _library.load_all()

        return jsonify({
            "attacks": [_attack_to_dict(a) for a in attacks],
            "total": len(attacks),
        })

    @app.route("/api/attacks/<name>", methods=["GET"])
    def get_attack(name: str):
        """Return details for a single attack by name."""
        all_attacks = _library.load_all()
        match = next((a for a in all_attacks if a.name == name), None)
        if not match:
            return jsonify({"error": f"Attack '{name}' not found"}), 404
        return jsonify({"attack": _attack_to_dict(match)})

    # ------------------------------------------------------------------
    # Targets route
    # ------------------------------------------------------------------

    @app.route("/api/targets", methods=["GET"])
    def list_targets():
        """Return the list of supported target providers."""
        targets = [
            {
                "type": "openai",
                "label": "OpenAI",
                "models": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"],
                "requires_api_key": True,
            },
            {
                "type": "anthropic",
                "label": "Anthropic",
                "models": ["claude-sonnet-4-20250514", "claude-3-haiku-20240307"],
                "requires_api_key": True,
            },
            {
                "type": "custom",
                "label": "Custom HTTP Endpoint",
                "models": [],
                "requires_api_key": False,
                "requires_url": True,
            },
            {
                "type": "local",
                "label": "Local Model",
                "models": [],
                "requires_api_key": False,
            },
        ]
        return jsonify({"targets": targets})

    # ------------------------------------------------------------------
    # OWASP scorecard
    # ------------------------------------------------------------------

    @app.route("/api/owasp", methods=["GET"])
    def owasp_scorecard():
        """Return an OWASP LLM Top 10 scorecard for a campaign.

        Query params:
            campaign_id (required): The campaign to score.
        """
        campaign_id_str = request.args.get("campaign_id")
        if not campaign_id_str:
            return jsonify({"error": "Query parameter 'campaign_id' is required"}), 400

        try:
            campaign_id = int(campaign_id_str)
        except ValueError:
            return jsonify({"error": "'campaign_id' must be an integer"}), 400

        campaign = db.get_campaign(campaign_id, resolved_db)
        if not campaign:
            return jsonify({"error": "Campaign not found"}), 404

        summary = db.get_summary(campaign_id, resolved_db)
        owasp_hits = summary.get("owasp_breakdown", {})

        scorecard: List[Dict[str, Any]] = []
        for owasp_id, label in OWASP_LLM_TOP_10.items():
            count = owasp_hits.get(owasp_id, 0)
            scorecard.append({
                "id": owasp_id,
                "name": label,
                "findings": count,
                "status": "fail" if count > 0 else "pass",
            })

        return jsonify({
            "campaign_id": campaign_id,
            "scorecard": scorecard,
        })

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    @app.route("/api/report/<int:campaign_id>", methods=["POST"])
    def generate_report(campaign_id: int):
        """Generate a report for a campaign.

        Accepts an optional ``format`` field in the JSON body (default
        ``"json"``).  Currently returns a JSON summary; HTML/Markdown
        generation is delegated to the Reporter module when available.
        """
        campaign = db.get_campaign(campaign_id, resolved_db)
        if not campaign:
            return jsonify({"error": "Campaign not found"}), 404

        data = request.get_json(silent=True) or {}
        report_format = data.get("format", "json")

        summary = db.get_summary(campaign_id, resolved_db)
        results = db.get_results(campaign_id, resolved_db)

        report = {
            "campaign": campaign,
            "summary": summary,
            "results": results,
            "format": report_format,
        }

        return jsonify({"report": report})

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    @app.route("/api/status", methods=["GET"])
    def status():
        """Server health check."""
        return jsonify({
            "status": "healthy",
            "service": "phantom",
            "version": "0.1.0",
            "database": resolved_db,
        })

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _attack_to_dict(attack: Attack) -> Dict[str, Any]:
    """Serialise an :class:`Attack` dataclass to a JSON-friendly dict."""
    prompt = attack.prompt
    if isinstance(prompt, list):
        prompt = prompt  # keep as list for multi-turn
    return {
        "name": attack.name,
        "category": attack.category,
        "technique": attack.technique,
        "prompt": prompt,
        "description": attack.description,
        "severity": attack.severity,
        "owasp_category": attack.owasp_category,
        "owasp_label": attack.owasp_label,
        "tags": attack.tags,
        "mutation_compatible": attack.mutation_compatible,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the development server on port 8666."""
    app = create_app()
    port = int(os.environ.get("PHANTOM_PORT", _DEFAULT_PORT))
    debug = os.environ.get("PHANTOM_DEBUG", "0") == "1"
    logger.info("Starting Phantom API server on port %d", port)
    app.run(host="0.0.0.0", port=port, debug=debug)


if __name__ == "__main__":
    main()
