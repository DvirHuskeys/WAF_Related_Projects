from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import duckdb

WAREHOUSE_PATH = Path("data/warehouse.db")


def get_connection():
    WAREHOUSE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(str(WAREHOUSE_PATH))
    _ensure_tables(conn)
    return conn


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
        CREATE TABLE IF NOT EXISTS managed_rules (
            vendor TEXT,
            rule_id TEXT,
            name TEXT,
            category TEXT,
            detection_pattern TEXT,
            mitigation TEXT,
            severity TEXT,
            metadata JSON
        )
        """
    )


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

