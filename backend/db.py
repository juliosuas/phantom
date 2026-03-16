"""Database layer for Phantom using SQLite.

Provides schema creation, CRUD operations for campaigns and attack results,
and summary statistics generation.  All public functions accept an optional
*db_path* parameter that defaults to ``phantom.db`` in the working directory.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional

_DEFAULT_DB_PATH = "phantom.db"

# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------


@contextmanager
def _connect(db_path: str = _DEFAULT_DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    """Yield a SQLite connection with row-factory set to ``sqlite3.Row``.

    The connection is committed on normal exit and rolled back on exception.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert a ``sqlite3.Row`` to a plain dictionary."""
    return dict(row)


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS campaigns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    target_type     TEXT    NOT NULL DEFAULT 'openai',
    target_model    TEXT    NOT NULL DEFAULT 'gpt-4',
    target_url      TEXT,
    preset          TEXT    NOT NULL DEFAULT 'standard',
    status          TEXT    NOT NULL DEFAULT 'pending',
    created_at      TEXT    NOT NULL,
    started_at      TEXT,
    completed_at    TEXT
);

CREATE TABLE IF NOT EXISTS attack_results (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id       INTEGER NOT NULL,
    attack_name       TEXT    NOT NULL,
    category          TEXT    NOT NULL DEFAULT '',
    owasp_id          TEXT    NOT NULL DEFAULT '',
    technique         TEXT    NOT NULL DEFAULT '',
    prompt_sent       TEXT    NOT NULL,
    response_received TEXT    NOT NULL DEFAULT '',
    success           INTEGER NOT NULL DEFAULT 0,
    severity          TEXT    NOT NULL DEFAULT 'info',
    confidence        REAL    NOT NULL DEFAULT 0.0,
    evidence          TEXT    NOT NULL DEFAULT '',
    timestamp         TEXT    NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_results_campaign
    ON attack_results(campaign_id);
CREATE INDEX IF NOT EXISTS idx_results_category
    ON attack_results(category);
CREATE INDEX IF NOT EXISTS idx_results_owasp
    ON attack_results(owasp_id);
"""


def init_db(db_path: str = _DEFAULT_DB_PATH) -> None:
    """Create the database tables if they do not already exist.

    Safe to call multiple times; uses ``CREATE TABLE IF NOT EXISTS``.

    Args:
        db_path: Filesystem path to the SQLite database file.
    """
    with _connect(db_path) as conn:
        conn.executescript(_SCHEMA_SQL)


# ---------------------------------------------------------------------------
# Campaign CRUD
# ---------------------------------------------------------------------------


def save_campaign(campaign: Dict[str, Any], db_path: str = _DEFAULT_DB_PATH) -> int:
    """Insert a new campaign and return its auto-generated ID.

    Required keys in *campaign*: ``name``.
    Optional keys: ``description``, ``target_type``, ``target_model``,
    ``target_url``, ``preset``, ``status``.

    Args:
        campaign: Dictionary of campaign attributes.
        db_path: Database file path.

    Returns:
        The integer primary key of the newly inserted row.
    """
    now = datetime.now(timezone.utc).isoformat()
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO campaigns
                (name, description, target_type, target_model, target_url,
                 preset, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                campaign.get("name", "Untitled"),
                campaign.get("description", ""),
                campaign.get("target_type", "openai"),
                campaign.get("target_model", "gpt-4"),
                campaign.get("target_url"),
                campaign.get("preset", "standard"),
                campaign.get("status", "pending"),
                now,
            ),
        )
        return cursor.lastrowid  # type: ignore[return-value]


def get_campaign(campaign_id: int, db_path: str = _DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Fetch a single campaign by ID.

    Args:
        campaign_id: Primary key of the campaign.
        db_path: Database file path.

    Returns:
        A dictionary of campaign attributes, or ``None`` if not found.
    """
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def list_campaigns(db_path: str = _DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Return all campaigns ordered by creation date descending.

    Args:
        db_path: Database file path.

    Returns:
        List of campaign dictionaries.
    """
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM campaigns ORDER BY created_at DESC"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def update_campaign_status(
    campaign_id: int,
    status: str,
    db_path: str = _DEFAULT_DB_PATH,
) -> None:
    """Update the status of a campaign.

    When *status* is ``"running"``, the ``started_at`` timestamp is set.
    When *status* is ``"completed"`` or ``"failed"``, the ``completed_at``
    timestamp is set.

    Args:
        campaign_id: Primary key of the campaign.
        status: New status string (e.g. ``"running"``, ``"completed"``).
        db_path: Database file path.
    """
    now = datetime.now(timezone.utc).isoformat()
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE campaigns SET status = ? WHERE id = ?",
            (status, campaign_id),
        )
        if status == "running":
            conn.execute(
                "UPDATE campaigns SET started_at = ? WHERE id = ?",
                (now, campaign_id),
            )
        elif status in ("completed", "failed"):
            conn.execute(
                "UPDATE campaigns SET completed_at = ? WHERE id = ?",
                (now, campaign_id),
            )


def delete_campaign(campaign_id: int, db_path: str = _DEFAULT_DB_PATH) -> bool:
    """Delete a campaign and its associated results.

    Args:
        campaign_id: Primary key of the campaign to remove.
        db_path: Database file path.

    Returns:
        ``True`` if a row was deleted, ``False`` if the ID was not found.
    """
    with _connect(db_path) as conn:
        # Results are cascade-deleted via FK, but be explicit for safety.
        conn.execute(
            "DELETE FROM attack_results WHERE campaign_id = ?", (campaign_id,)
        )
        cursor = conn.execute(
            "DELETE FROM campaigns WHERE id = ?", (campaign_id,)
        )
        return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Attack result CRUD
# ---------------------------------------------------------------------------


def save_result(result: Dict[str, Any], db_path: str = _DEFAULT_DB_PATH) -> int:
    """Insert an attack result row and return its ID.

    Required keys: ``campaign_id``, ``attack_name``, ``prompt_sent``.
    Optional keys: ``category``, ``owasp_id``, ``technique``,
    ``response_received``, ``success``, ``severity``, ``confidence``,
    ``evidence``.

    Args:
        result: Dictionary of result attributes.
        db_path: Database file path.

    Returns:
        The integer primary key of the newly inserted row.
    """
    now = datetime.now(timezone.utc).isoformat()
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO attack_results
                (campaign_id, attack_name, category, owasp_id, technique,
                 prompt_sent, response_received, success, severity,
                 confidence, evidence, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["campaign_id"],
                result["attack_name"],
                result.get("category", ""),
                result.get("owasp_id", ""),
                result.get("technique", ""),
                result["prompt_sent"],
                result.get("response_received", ""),
                1 if result.get("success") else 0,
                result.get("severity", "info"),
                result.get("confidence", 0.0),
                result.get("evidence", ""),
                result.get("timestamp", now),
            ),
        )
        return cursor.lastrowid  # type: ignore[return-value]


def get_results(
    campaign_id: int,
    db_path: str = _DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """Return all attack results for a campaign, newest first.

    Args:
        campaign_id: Campaign to query.
        db_path: Database file path.

    Returns:
        List of result dictionaries.
    """
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT * FROM attack_results
            WHERE campaign_id = ?
            ORDER BY timestamp DESC
            """,
            (campaign_id,),
        ).fetchall()
        results = []
        for r in rows:
            d = _row_to_dict(r)
            d["success"] = bool(d["success"])
            results.append(d)
        return results


def get_summary(
    campaign_id: int,
    db_path: str = _DEFAULT_DB_PATH,
) -> Dict[str, Any]:
    """Compute summary statistics for a campaign.

    Args:
        campaign_id: Campaign to summarise.
        db_path: Database file path.

    Returns:
        Dictionary with keys: ``total_attacks``, ``successful_attacks``,
        ``success_rate``, ``severity_breakdown``, ``category_breakdown``,
        ``owasp_breakdown``.
    """
    with _connect(db_path) as conn:
        total_row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM attack_results WHERE campaign_id = ?",
            (campaign_id,),
        ).fetchone()
        total = total_row["cnt"] if total_row else 0

        success_row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM attack_results WHERE campaign_id = ? AND success = 1",
            (campaign_id,),
        ).fetchone()
        successes = success_row["cnt"] if success_row else 0

        # Severity breakdown (successful attacks only)
        severity_rows = conn.execute(
            """
            SELECT severity, COUNT(*) AS cnt
            FROM attack_results
            WHERE campaign_id = ? AND success = 1
            GROUP BY severity
            """,
            (campaign_id,),
        ).fetchall()
        severity_breakdown = {r["severity"]: r["cnt"] for r in severity_rows}

        # Category breakdown (successful attacks only)
        category_rows = conn.execute(
            """
            SELECT category, COUNT(*) AS cnt
            FROM attack_results
            WHERE campaign_id = ? AND success = 1
            GROUP BY category
            """,
            (campaign_id,),
        ).fetchall()
        category_breakdown = {r["category"]: r["cnt"] for r in category_rows}

        # OWASP breakdown (successful attacks only)
        owasp_rows = conn.execute(
            """
            SELECT owasp_id, COUNT(*) AS cnt
            FROM attack_results
            WHERE campaign_id = ? AND success = 1 AND owasp_id != ''
            GROUP BY owasp_id
            """,
            (campaign_id,),
        ).fetchall()
        owasp_breakdown = {r["owasp_id"]: r["cnt"] for r in owasp_rows}

        return {
            "total_attacks": total,
            "successful_attacks": successes,
            "success_rate": round(successes / total, 4) if total else 0.0,
            "severity_breakdown": severity_breakdown,
            "category_breakdown": category_breakdown,
            "owasp_breakdown": owasp_breakdown,
        }
