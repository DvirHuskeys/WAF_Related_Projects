from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import duckdb

WAREHOUSE_PATH = Path("data/warehouse.db")


def get_connection():
    WAREHOUSE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(str(WAREHOUSE_PATH))
    _enable_json(conn)
    _ensure_tables(conn)
    return conn


def initialize_schema() -> Dict[str, int]:
    """
    Create the DuckDB file and required tables, returning row counts.

    Used by scripts/init_duckdb.py so developers can bootstrap the warehouse from
    the CLI without depending on Streamlit/CLI side effects.
    """
    WAREHOUSE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with duckdb.connect(str(WAREHOUSE_PATH)) as conn:
        _enable_json(conn)
        _ensure_tables(conn)
        stats = {}
        for table in (
            "domain_enrichment",
            "managed_rules",
            "job_runs",
            "persona_usage",
            "rule_notes",
            "activity_log",
        ):
            stats[table] = conn.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
    return stats


def _enable_json(conn):
    conn.execute("INSTALL json")
    conn.execute("LOAD json")


def _ensure_tables(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS domain_enrichment (
            domain TEXT PRIMARY KEY,
            detected_waf TEXT,
            detected_cdn TEXT,
            config_drift_score DOUBLE,
            downtime_risk_score DOUBLE,
            attack_surface_score DOUBLE,
            last_observed TIMESTAMP,
            raw JSON
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS job_runs (
            job_id TEXT PRIMARY KEY,
            job_type TEXT,
            started_at TIMESTAMP,
            finished_at TIMESTAMP,
            status TEXT,
            details JSON
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS managed_rules (
            vendor TEXT,
            rule_id TEXT,
            name TEXT,
            category TEXT,
            detection_pattern TEXT,
            mitigation TEXT,
            severity TEXT,
            metadata JSON,
            source TEXT,
            synced_at TIMESTAMP,
            PRIMARY KEY (vendor, rule_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS persona_usage (
            id TEXT PRIMARY KEY,
            persona_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            action TEXT NOT NULL,
            channel TEXT NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rule_notes (
            note_id TEXT PRIMARY KEY,
            rule_vendor TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP,
            deleted_at TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS activity_log (
            id TEXT PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            author TEXT,
            role TEXT,
            action TEXT,
            target TEXT,
            details JSON,
            status TEXT DEFAULT 'success'
        )
        """
    )
    _ensure_rule_metadata_columns(conn)


def _ensure_rule_metadata_columns(conn):
    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info('managed_rules')").fetchall()
    }
    if "source" not in columns:
        conn.execute("ALTER TABLE managed_rules ADD COLUMN source TEXT")
    if "synced_at" not in columns:
        conn.execute("ALTER TABLE managed_rules ADD COLUMN synced_at TIMESTAMP")


def fetch_domain(domain: str) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM domain_enrichment WHERE domain = ?", [domain]
        ).fetchall()
        columns = [desc[0] for desc in conn.description]
    if not rows:
        return None
    return dict(zip(columns, rows[0]))


def list_domains(limit: int = 50) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM domain_enrichment ORDER BY last_observed DESC LIMIT ?",
            [limit],
        ).fetchall()
        columns = [desc[0] for desc in conn.description]
    return [dict(zip(columns, row)) for row in rows]


def list_rules(limit: int = 2000) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                vendor,
                rule_id,
                name,
                category,
                severity,
                detection_pattern,
                mitigation,
                metadata,
                source,
                synced_at
            FROM managed_rules
            ORDER BY vendor, rule_id
            LIMIT ?
            """,
            [limit],
        ).fetchall()
        columns = [desc[0] for desc in conn.description]
    return [dict(zip(columns, row)) for row in rows]

