#!/usr/bin/env python3
from __future__ import annotations

"""
Seed DuckDB with demo domains and Cloudflare rules so Streamlit can showcase data.

Usage:
    python scripts/seed_sample_data.py
"""

import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Dict, Iterable, Tuple

import typer

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services import storage
from scripts.rule_sync import cloudflare

app = typer.Typer(add_completion=False)

DOMAINS_CSV = ROOT / "data/samples/domains.csv"
RULES_JSON = ROOT / "data/rules/cloudflare_sample.json"


def _domain_payload(domain: str, idx: int) -> Dict[str, object]:
    waf_options = ["Cloudflare", "AWS WAF", "Fastly", "Cloudflare"]
    cdn_options = ["Cloudflare", "Akamai", "Fastly", "Cloudflare"]
    base_scores = [0.62, 0.41, 0.77, 0.55]
    pos = idx % len(base_scores)
    return {
        "domain": domain,
        "detected_waf": waf_options[pos],
        "detected_cdn": cdn_options[pos],
        "config_drift_score": round(base_scores[pos], 2),
        "downtime_risk_score": round(base_scores[-(pos + 1)], 2),
        "attack_surface_score": round(0.35 + pos * 0.1, 2),
        "last_observed": datetime.now(timezone.utc).isoformat(),
        "raw": json.dumps(
            {
            "source": "sample_loader",
            "notes": "Deterministic demo payload",
            "generated_at": datetime.utcnow().isoformat(),
            }
        ),
    }


def seed_domains(conn, csv_path: Path) -> int:
    if not csv_path.exists():
        raise FileNotFoundError(f"Sample CSV missing: {csv_path}")
    typer.echo(f"→ Loading domains from {csv_path}")
    inserted = 0
    with csv_path.open() as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader):
            domain = (row.get("domain") or "").strip()
            if not domain:
                continue
            payload = _domain_payload(domain, idx)
            conn.execute(
                "DELETE FROM domain_enrichment WHERE domain = ?", [payload["domain"]]
            )
            conn.execute(
                """
                INSERT INTO domain_enrichment (
                    domain, detected_waf, detected_cdn,
                    config_drift_score, downtime_risk_score, attack_surface_score,
                    last_observed, raw
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    payload["domain"],
                    payload["detected_waf"],
                    payload["detected_cdn"],
                    payload["config_drift_score"],
                    payload["downtime_risk_score"],
                    payload["attack_surface_score"],
                    payload["last_observed"],
                    payload["raw"],
                ],
            )
            inserted += 1
    return inserted


def seed_rules(conn, rules_path: Path) -> int:
    if not rules_path.exists():
        raise FileNotFoundError(f"Sample rules missing: {rules_path}")
    typer.echo(f"→ Loading Cloudflare rules from {rules_path}")
    rules = cloudflare.load_rules(rules_path)
    for rule in rules:
        conn.execute(
            "DELETE FROM managed_rules WHERE vendor = ? AND rule_id = ?",
            [rule["vendor"], rule["rule_id"]],
        )
        conn.execute(
            """
            INSERT INTO managed_rules (
                vendor, rule_id, name, category,
                detection_pattern, mitigation, severity, metadata,
                source, synced_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                rule["vendor"],
                rule["rule_id"],
                rule["name"],
                rule["category"],
                rule["detection_pattern"],
                rule["mitigation"],
                rule["severity"],
                rule["metadata"],
                rule["source"],
                rule["synced_at"],
            ],
        )
    return len(rules)


@app.command()
def main(reset: bool = typer.Option(False, help="Wipe tables before seeding.")) -> None:
    """
    Populate DuckDB with deterministic demo data for Story 1.4.
    """

    try:
        conn = storage.get_connection()
    except Exception as exc:  # pragma: no cover - CLI surface
        typer.secho(f"Failed to open DuckDB: {exc}", fg="red")
        raise typer.Exit(1)

    try:
        if reset:
            typer.echo("→ Resetting existing data")
            conn.execute("DELETE FROM domain_enrichment")
            conn.execute("DELETE FROM managed_rules")
        domain_count = seed_domains(conn, DOMAINS_CSV)
        rule_count = seed_rules(conn, RULES_JSON)
    except Exception as exc:  # pragma: no cover - CLI surface
        typer.secho(f"Seeding failed: {exc}", fg="red")
        raise typer.Exit(1)

    typer.secho(
        f"✅ Seed complete: {domain_count} domains, {rule_count} rules.", fg="green"
    )
    typer.echo("Next: run `streamlit run ui/app.py` (or refresh an open session).")


if __name__ == "__main__":
    app()


