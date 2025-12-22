from __future__ import annotations

import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import typer

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from backend.services import fingerprint, jobs, scoring, storage

app = typer.Typer(add_completion=False)

DOMAIN_PATTERN = re.compile(r"^(?!-)([a-zA-Z0-9-]+)(\.[a-zA-Z0-9-]+)+$")


class Summary:
    def __init__(self) -> None:
        self.processed = 0
        self.inserted = 0
        self.skipped_invalid = 0
        self.skipped_duplicate = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "processed": self.processed,
            "inserted": self.inserted,
            "skipped_invalid": self.skipped_invalid,
            "skipped_duplicate": self.skipped_duplicate,
        }


@app.command()
def ingest(
    csv_path: Path = typer.Argument(..., help="CSV file with a 'domain' column"),
    limit: int = typer.Option(0, help="Max domains to process (0 = all)"),
    dry_run: bool = typer.Option(False, help="Show changes without writing to DuckDB"),
) -> None:
    """
    Enrich domains from a CSV file and load them into DuckDB.
    """

    try:
        domains = _load_domains(csv_path)
    except Exception as exc:
        typer.secho(f"Failed to read CSV: {exc}", fg=typer.colors.RED)
        raise typer.Exit(1)

    if limit:
        domains = domains[:limit]

    summary = Summary()
    job_id = jobs.start_job(
        "domain_enrich",
        {"records": len(domains), "dry_run": dry_run, "limit": limit},
    )
    typer.echo(f"Starting ingestion job: {job_id}")

    try:
        _process_domains(domains, summary, dry_run)
    except Exception as exc:
        jobs.complete_job(
            job_id,
            "failed",
            {**summary.as_dict(), "dry_run": dry_run, "error": str(exc)},
        )
        raise
    else:
        jobs.complete_job(job_id, "success", {**summary.as_dict(), "dry_run": dry_run})
        _print_summary(summary, job_id, dry_run)


def _process_domains(domains: List[str], summary: Summary, dry_run: bool) -> None:
    seen = set()
    try:
        conn = storage.get_connection()
    except Exception as exc:
        typer.secho(f"DuckDB connection failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(1)

    with typer.progressbar(domains, label="Enriching domains") as progress_iterable:
        with conn:
            for domain in progress_iterable:
                summary.processed += 1
                normalized = domain.strip().lower()
                if not _is_valid_domain(normalized):
                    summary.skipped_invalid += 1
                    typer.secho(
                        f"[!] Skipping invalid domain '{domain}'", fg=typer.colors.YELLOW
                    )
                    continue
                if normalized in seen:
                    summary.skipped_duplicate += 1
                    typer.secho(
                        f"[!] Duplicate domain '{domain}' skipped",
                        fg=typer.colors.YELLOW,
                    )
                    continue

                seen.add(normalized)
                if dry_run:
                    typer.echo(f"[dry-run] Would enrich {normalized}")
                    continue

                stack = fingerprint.detect_stack(normalized)
                scores = scoring.derive_scores(normalized, stack["detected_waf"])
                payload = {
                    "domain": normalized,
                    "detected_waf": stack["detected_waf"],
                    "detected_cdn": stack["detected_cdn"],
                    "config_drift_score": scores["config_drift"],
                    "downtime_risk_score": scores["downtime_risk"],
                    "attack_surface_score": scores["attack_surface"],
                    "last_observed": datetime.utcnow(),
                    "raw": json.dumps(stack),
                }
                conn.execute(
                    """
                    INSERT OR REPLACE INTO domain_enrichment VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        payload["domain"],
                        payload["detected_waf"],
                        payload["detected_cdn"],
                        payload["config_drift_score"],
                        payload["downtime_risk_score"],
                        payload["attack_surface_score"],
                        payload["last_observed"],
                        payload["raw"],
                    ),
                )
                summary.inserted += 1
                typer.secho(
                    f"[+] {normalized} → {stack['detected_waf']}/{stack['detected_cdn']} "
                    f"drift {scores['config_drift']:.2f}",
                    fg=typer.colors.GREEN,
                )


def _load_domains(csv_path: Path) -> List[str]:
    if not csv_path.exists():
        raise FileNotFoundError(f"{csv_path} does not exist")
    with csv_path.open() as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "domain" not in reader.fieldnames:
            raise ValueError("CSV must contain a 'domain' column")
        return [row["domain"].strip() for row in reader if row.get("domain")]


def _is_valid_domain(domain: str) -> bool:
    return bool(domain and DOMAIN_PATTERN.match(domain))


def _print_summary(summary: Summary, job_id: str, dry_run: bool) -> None:
    typer.echo("")
    typer.echo("Ingestion Summary")
    typer.echo("-----------------")
    for key, value in summary.as_dict().items():
        typer.echo(f"{key.replace('_', ' ').title()}: {value}")
    typer.echo(f"Job Reference: {job_id}{' (dry run)' if dry_run else ''}")
    typer.echo("Next steps: run `streamlit run ui/app.py` to view results.")


if __name__ == "__main__":
    app()

