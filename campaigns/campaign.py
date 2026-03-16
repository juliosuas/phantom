"""Campaign management for Phantom red-teaming engagements.

A campaign groups a set of adversarial attacks into a single trackable
unit with lifecycle management (create, run, pause, resume), persistent
storage, and result aggregation.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from campaigns.presets import CampaignPresets


class CampaignStatus(Enum):
    """Lifecycle status of a campaign."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Campaign:
    """A single red-teaming campaign against a target LLM.

    A campaign encapsulates the full configuration and state for an
    assessment run, including which attack categories to use, the target
    configuration, and all collected results.

    Attributes:
        id: Unique identifier for the campaign.
        name: Human-readable campaign name.
        description: Optional longer description of the campaign's purpose.
        target_config: Dictionary describing the target LLM endpoint
            (e.g. provider, model, URL, API key reference).
        attack_categories: List of attack category names to include.
        status: Current lifecycle status.
        created_at: ISO-8601 timestamp of creation.
        started_at: ISO-8601 timestamp when execution began, or None.
        completed_at: ISO-8601 timestamp when execution finished, or None.
        results: Accumulated attack results from the run.
        preset_name: Name of the preset used to configure this campaign,
            or None if manually configured.
    """

    id: str
    name: str
    description: str = ""
    target_config: Dict[str, Any] = field(default_factory=dict)
    attack_categories: List[str] = field(default_factory=list)
    status: CampaignStatus = CampaignStatus.PENDING
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    results: List[Dict[str, Any]] = field(default_factory=list)
    preset_name: Optional[str] = None


class CampaignManager:
    """Manages the full lifecycle of red-teaming campaigns.

    Provides CRUD operations, execution orchestration, and result
    aggregation for campaigns persisted in a local SQLite database.

    Args:
        db_path: Filesystem path to the SQLite database file. Created
            automatically if it does not exist.
    """

    def __init__(self, db_path: str = "phantom.db") -> None:
        self._db_path = db_path
        self._active_campaign: Optional[str] = None
        self._paused: bool = False
        self._init_db()

    # ------------------------------------------------------------------
    # Database bootstrap
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create the campaigns and results tables if they do not exist."""
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS campaigns (
                    id              TEXT PRIMARY KEY,
                    name            TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    target_config   TEXT NOT NULL DEFAULT '{}',
                    attack_categories TEXT NOT NULL DEFAULT '[]',
                    status          TEXT NOT NULL DEFAULT 'pending',
                    created_at      TEXT NOT NULL,
                    started_at      TEXT,
                    completed_at    TEXT,
                    preset_name     TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS campaign_results (
                    id              TEXT PRIMARY KEY,
                    campaign_id     TEXT NOT NULL,
                    attack_name     TEXT NOT NULL,
                    category        TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    success         INTEGER NOT NULL DEFAULT 0,
                    details         TEXT NOT NULL DEFAULT '{}',
                    created_at      TEXT NOT NULL,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                        ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_results_campaign
                ON campaign_results(campaign_id)
                """
            )

    def _connect(self) -> sqlite3.Connection:
        """Return a new database connection with WAL mode enabled."""
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create(
        self,
        name: str,
        target_config: Dict[str, Any],
        categories: Optional[List[str]] = None,
        preset: Optional[str] = None,
    ) -> Campaign:
        """Create a new campaign and persist it.

        If a *preset* name is provided, its configuration is merged into
        the campaign.  Explicitly supplied *categories* override the
        preset's defaults.

        Args:
            name: Human-readable campaign name.
            target_config: Target LLM connection details.
            categories: Attack categories to include.  Defaults to all
                categories defined in the preset or a sensible default set.
            preset: Optional preset name (e.g. ``QUICK_SCAN``).

        Returns:
            The newly created :class:`Campaign` instance.

        Raises:
            ValueError: If an unknown preset name is given.
        """
        preset_config: Dict[str, Any] = {}
        if preset is not None:
            preset_config = CampaignPresets.get_preset(preset)

        resolved_categories = categories or preset_config.get(
            "categories",
            ["prompt_injection", "jailbreak", "extraction", "encoding"],
        )

        campaign = Campaign(
            id=uuid.uuid4().hex,
            name=name,
            target_config=target_config,
            attack_categories=resolved_categories,
            preset_name=preset,
        )

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO campaigns
                    (id, name, description, target_config, attack_categories,
                     status, created_at, started_at, completed_at, preset_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    campaign.id,
                    campaign.name,
                    campaign.description,
                    json.dumps(campaign.target_config),
                    json.dumps(campaign.attack_categories),
                    campaign.status.value,
                    campaign.created_at,
                    campaign.started_at,
                    campaign.completed_at,
                    campaign.preset_name,
                ),
            )

        return campaign

    def get(self, campaign_id: str) -> Campaign:
        """Retrieve a campaign by its unique identifier.

        Args:
            campaign_id: The campaign's ID.

        Returns:
            The matching :class:`Campaign`.

        Raises:
            KeyError: If no campaign with the given ID exists.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
            ).fetchone()

        if row is None:
            raise KeyError(f"Campaign not found: {campaign_id}")

        return self._row_to_campaign(row)

    def list_all(self) -> List[Dict[str, Any]]:
        """Return summary dicts for every campaign, newest first.

        Each summary contains ``id``, ``name``, ``status``, ``created_at``,
        ``preset_name``, and ``attack_count``.

        Returns:
            A list of campaign summary dictionaries.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT c.id, c.name, c.status, c.created_at, c.preset_name,
                       COUNT(r.id) AS attack_count
                FROM campaigns c
                LEFT JOIN campaign_results r ON r.campaign_id = c.id
                GROUP BY c.id
                ORDER BY c.created_at DESC
                """
            ).fetchall()

        return [
            {
                "id": r["id"],
                "name": r["name"],
                "status": r["status"],
                "created_at": r["created_at"],
                "preset_name": r["preset_name"],
                "attack_count": r["attack_count"],
            }
            for r in rows
        ]

    def delete(self, campaign_id: str) -> None:
        """Delete a campaign and all associated results.

        Args:
            campaign_id: The campaign's ID.

        Raises:
            KeyError: If the campaign does not exist.
        """
        # Verify existence first.
        self.get(campaign_id)

        with self._connect() as conn:
            conn.execute("DELETE FROM campaign_results WHERE campaign_id = ?", (campaign_id,))
            conn.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))

    # ------------------------------------------------------------------
    # Execution lifecycle
    # ------------------------------------------------------------------

    def run(
        self,
        campaign_id: str,
        progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    ) -> Campaign:
        """Execute a campaign by running all configured attacks.

        The method loads the appropriate attacks based on the campaign's
        categories and optional preset, feeds them through the Phantom
        engine, and persists each result.  An optional *progress_callback*
        is invoked after every individual attack with ``(current, total,
        result_dict)``.

        Args:
            campaign_id: ID of the campaign to run.
            progress_callback: Optional callback for progress reporting.

        Returns:
            The completed (or failed) :class:`Campaign`.

        Raises:
            KeyError: If the campaign does not exist.
            RuntimeError: If the campaign is not in a runnable state.
        """
        campaign = self.get(campaign_id)

        if campaign.status not in (CampaignStatus.PENDING, CampaignStatus.PAUSED):
            raise RuntimeError(
                f"Campaign '{campaign_id}' is in state '{campaign.status.value}' "
                "and cannot be started. Only PENDING or PAUSED campaigns can run."
            )

        self._paused = False
        self._active_campaign = campaign_id
        now = datetime.now(timezone.utc).isoformat()

        self._update_status(campaign_id, CampaignStatus.RUNNING, started_at=now)

        try:
            results = self._execute_attacks(campaign, progress_callback)
            self._store_results(campaign_id, results)

            completed_at = datetime.now(timezone.utc).isoformat()

            if self._paused:
                self._update_status(campaign_id, CampaignStatus.PAUSED)
            else:
                self._update_status(
                    campaign_id,
                    CampaignStatus.COMPLETED,
                    completed_at=completed_at,
                )

        except Exception:
            self._update_status(campaign_id, CampaignStatus.FAILED)
            raise
        finally:
            self._active_campaign = None

        return self.get(campaign_id)

    def pause(self, campaign_id: str) -> None:
        """Signal a running campaign to pause after the current attack.

        Args:
            campaign_id: The campaign's ID.

        Raises:
            RuntimeError: If the campaign is not currently running.
        """
        campaign = self.get(campaign_id)
        if campaign.status != CampaignStatus.RUNNING:
            raise RuntimeError(
                f"Cannot pause campaign in state '{campaign.status.value}'"
            )

        self._paused = True

    def resume(self, campaign_id: str) -> None:
        """Resume a paused campaign from where it left off.

        Internally delegates to :meth:`run`, which detects the PAUSED
        state and continues execution.

        Args:
            campaign_id: The campaign's ID.

        Raises:
            RuntimeError: If the campaign is not paused.
        """
        campaign = self.get(campaign_id)
        if campaign.status != CampaignStatus.PAUSED:
            raise RuntimeError(
                f"Cannot resume campaign in state '{campaign.status.value}'"
            )

        self.run(campaign_id)

    # ------------------------------------------------------------------
    # Results & reporting
    # ------------------------------------------------------------------

    def get_results(self, campaign_id: str) -> List[Dict[str, Any]]:
        """Return all attack results for a campaign.

        Args:
            campaign_id: The campaign's ID.

        Returns:
            A list of result dictionaries, each containing ``id``,
            ``attack_name``, ``category``, ``severity``, ``success``,
            ``details``, and ``created_at``.

        Raises:
            KeyError: If the campaign does not exist.
        """
        self.get(campaign_id)  # ensure exists

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, attack_name, category, severity, success,
                       details, created_at
                FROM campaign_results
                WHERE campaign_id = ?
                ORDER BY created_at ASC
                """,
                (campaign_id,),
            ).fetchall()

        return [
            {
                "id": r["id"],
                "attack_name": r["attack_name"],
                "category": r["category"],
                "severity": r["severity"],
                "success": bool(r["success"]),
                "details": json.loads(r["details"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def get_summary(self, campaign_id: str) -> Dict[str, Any]:
        """Compute aggregate statistics for a campaign's results.

        Args:
            campaign_id: The campaign's ID.

        Returns:
            A dictionary with keys:

            - ``total`` -- total number of attacks executed.
            - ``succeeded`` -- number of successful attacks.
            - ``failed`` -- number of unsuccessful attacks.
            - ``by_category`` -- dict mapping category name to counts.
            - ``by_severity`` -- dict mapping severity to counts.

        Raises:
            KeyError: If the campaign does not exist.
        """
        results = self.get_results(campaign_id)

        total = len(results)
        succeeded = sum(1 for r in results if r["success"])
        failed = total - succeeded

        by_category: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"total": 0, "succeeded": 0, "failed": 0}
        )
        by_severity: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"total": 0, "succeeded": 0, "failed": 0}
        )

        for r in results:
            cat = r["category"] or "unknown"
            sev = r["severity"] or "medium"

            by_category[cat]["total"] += 1
            by_severity[sev]["total"] += 1

            if r["success"]:
                by_category[cat]["succeeded"] += 1
                by_severity[sev]["succeeded"] += 1
            else:
                by_category[cat]["failed"] += 1
                by_severity[sev]["failed"] += 1

        return {
            "total": total,
            "succeeded": succeeded,
            "failed": failed,
            "by_category": dict(by_category),
            "by_severity": dict(by_severity),
        }

    def export_results(self, campaign_id: str, format: str = "json") -> str:
        """Export campaign results to a file.

        Args:
            campaign_id: The campaign's ID.
            format: Output format -- ``json``, ``csv``, or ``html``.

        Returns:
            The filesystem path to the exported file.

        Raises:
            KeyError: If the campaign does not exist.
            ValueError: If *format* is not supported.
        """
        supported_formats = {"json", "csv", "html"}
        if format not in supported_formats:
            raise ValueError(
                f"Unsupported export format '{format}'. "
                f"Choose from: {', '.join(sorted(supported_formats))}"
            )

        campaign = self.get(campaign_id)
        results = self.get_results(campaign_id)
        summary = self.get_summary(campaign_id)

        export_dir = Path("exports")
        export_dir.mkdir(parents=True, exist_ok=True)

        safe_name = "".join(
            c if c.isalnum() or c in "-_" else "_" for c in campaign.name
        )
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{safe_name}_{timestamp}.{format}"
        filepath = export_dir / filename

        if format == "json":
            payload = {
                "campaign": {
                    "id": campaign.id,
                    "name": campaign.name,
                    "description": campaign.description,
                    "status": campaign.status.value,
                    "preset_name": campaign.preset_name,
                    "created_at": campaign.created_at,
                    "started_at": campaign.started_at,
                    "completed_at": campaign.completed_at,
                },
                "summary": summary,
                "results": results,
            }
            filepath.write_text(
                json.dumps(payload, indent=2, default=str), encoding="utf-8"
            )

        elif format == "csv":
            import csv

            with open(filepath, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(
                    fh,
                    fieldnames=[
                        "id", "attack_name", "category", "severity",
                        "success", "created_at",
                    ],
                )
                writer.writeheader()
                for r in results:
                    writer.writerow({
                        "id": r["id"],
                        "attack_name": r["attack_name"],
                        "category": r["category"],
                        "severity": r["severity"],
                        "success": r["success"],
                        "created_at": r["created_at"],
                    })

        elif format == "html":
            html = self._render_html_report(campaign, summary, results)
            filepath.write_text(html, encoding="utf-8")

        return str(filepath)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _row_to_campaign(self, row: sqlite3.Row) -> Campaign:
        """Convert a database row into a Campaign dataclass."""
        return Campaign(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            target_config=json.loads(row["target_config"]),
            attack_categories=json.loads(row["attack_categories"]),
            status=CampaignStatus(row["status"]),
            created_at=row["created_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            preset_name=row["preset_name"],
        )

    def _update_status(
        self,
        campaign_id: str,
        status: CampaignStatus,
        started_at: Optional[str] = None,
        completed_at: Optional[str] = None,
    ) -> None:
        """Persist a status change and optional timestamp updates."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE campaigns
                SET status = ?,
                    started_at = COALESCE(?, started_at),
                    completed_at = COALESCE(?, completed_at)
                WHERE id = ?
                """,
                (status.value, started_at, completed_at, campaign_id),
            )

    def _execute_attacks(
        self,
        campaign: Campaign,
        progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]],
    ) -> List[Dict[str, Any]]:
        """Run attacks for a campaign through the Phantom engine.

        This method attempts to import and use the core engine. If the
        engine is not available (e.g. during testing), it returns an
        empty result set gracefully.

        Returns:
            A list of result dictionaries from executed attacks.
        """
        preset_config: Dict[str, Any] = {}
        if campaign.preset_name:
            preset_config = CampaignPresets.get_preset(campaign.preset_name)

        max_attacks: Optional[int] = preset_config.get("max_attacks")
        mutation_rounds: int = preset_config.get("mutation_rounds", 1)
        include_multi_turn: bool = preset_config.get("include_multi_turn", False)

        try:
            from core.engine import PhantomEngine
            from core.config import PhantomConfig

            config = PhantomConfig(
                target_type=campaign.target_config.get("target_type", "openai"),
                target_model=campaign.target_config.get("target_model", "gpt-4"),
                target_url=campaign.target_config.get("target_url"),
                api_key=campaign.target_config.get("api_key"),
                mutation_rounds=mutation_rounds,
                categories=campaign.attack_categories,
            )

            engine = PhantomEngine(config)
            raw_results = engine.run(
                categories=campaign.attack_categories,
                max_attacks=max_attacks,
                include_multi_turn=include_multi_turn,
            )
        except ImportError:
            raw_results = []

        collected: List[Dict[str, Any]] = []
        total = len(raw_results)

        for idx, raw in enumerate(raw_results):
            if self._paused:
                break

            result = {
                "attack_name": raw.get("attack_name", "unknown"),
                "category": raw.get("category", ""),
                "severity": raw.get("severity", "medium"),
                "success": raw.get("success", False),
                "details": raw.get("details", {}),
            }
            collected.append(result)

            if progress_callback is not None:
                progress_callback(idx + 1, total, result)

        return collected

    def _store_results(
        self, campaign_id: str, results: List[Dict[str, Any]]
    ) -> None:
        """Persist a batch of attack results to the database."""
        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO campaign_results
                    (id, campaign_id, attack_name, category, severity,
                     success, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        uuid.uuid4().hex,
                        campaign_id,
                        r["attack_name"],
                        r["category"],
                        r["severity"],
                        int(r["success"]),
                        json.dumps(r.get("details", {})),
                        now,
                    )
                    for r in results
                ],
            )

    @staticmethod
    def _render_html_report(
        campaign: Campaign,
        summary: Dict[str, Any],
        results: List[Dict[str, Any]],
    ) -> str:
        """Produce a self-contained HTML report string."""
        result_rows = "\n".join(
            f"<tr>"
            f"<td>{r['attack_name']}</td>"
            f"<td>{r['category']}</td>"
            f"<td>{r['severity']}</td>"
            f"<td>{'PASS' if r['success'] else 'FAIL'}</td>"
            f"</tr>"
            for r in results
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Phantom Report - {campaign.name}</title>
<style>
  body {{ font-family: sans-serif; margin: 2rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
  th {{ background: #f4f4f4; }}
  .stat {{ display: inline-block; margin-right: 2rem; }}
</style>
</head>
<body>
<h1>Phantom Campaign Report</h1>
<h2>{campaign.name}</h2>
<p>{campaign.description}</p>
<div>
  <span class="stat"><strong>Total:</strong> {summary['total']}</span>
  <span class="stat"><strong>Succeeded:</strong> {summary['succeeded']}</span>
  <span class="stat"><strong>Failed:</strong> {summary['failed']}</span>
</div>
<table>
<thead><tr><th>Attack</th><th>Category</th><th>Severity</th><th>Result</th></tr></thead>
<tbody>
{result_rows}
</tbody>
</table>
</body>
</html>"""
