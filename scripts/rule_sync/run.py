from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Callable, Dict, List, Tuple

import typer

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from backend.services import jobs, storage
from scripts.rule_sync import DEFAULT_ADAPTERS

REQUIRED_RULE_FIELDS = {
    "vendor",
    "rule_id",
    "name",
    "category",
    "detection_pattern",
    "mitigation",
    "severity",
    "metadata",
    "source",
    "synced_at",
}


def main(
    vendor: str = typer.Argument(..., help="Vendor id (e.g. cloudflare)"),
    source: Path = typer.Option(
        Path("data/rules/cloudflare_sample.json"),
        help="Path to vendor rule export",
    ),
    dry_run: bool = typer.Option(False, help="Preview sync without writing to DuckDB"),
) -> None:
    vendor = vendor.lower()
    module_path = DEFAULT_ADAPTERS.get(vendor, f"scripts.rule_sync.{vendor}")
    loader = _resolve_loader(module_path)

    try:
        rules = loader(source)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except Exception as exc:
        raise typer.BadParameter(f"Adapter error: {exc}") from exc

    validated_rules = [_validate_rule(rule) for rule in rules]
    job_id = jobs.start_job(
        "rule_sync",
        {"vendor": vendor, "records": len(validated_rules), "dry_run": dry_run},
    )
    typer.echo(f"Starting rule-sync job: {job_id}")

    try:
        inserted, updated = _persist_rules(validated_rules, dry_run)
    except Exception as exc:
        jobs.complete_job(
            job_id,
            "failed",
            {"vendor": vendor, "error": str(exc), "dry_run": dry_run},
        )
        raise
    else:
        jobs.complete_job(
            job_id,
            "success",
            {"vendor": vendor, "inserted": inserted, "updated": updated, "dry_run": dry_run},
        )
        _print_summary(vendor, inserted, updated, job_id, dry_run)


def _resolve_loader(path: str) -> Callable[[Path], List[dict]]:
    module_name, func_name = path, "load_rules"
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        raise typer.BadParameter(f"Adapter module '{module_name}' not found") from exc
    loader = getattr(module, func_name, None)
    if not loader:
        raise typer.BadParameter(f"{module_name}.{func_name} not found")
    return loader


def _validate_rule(rule: Dict) -> Dict:
    missing = REQUIRED_RULE_FIELDS - rule.keys()
    if missing:
        raise typer.BadParameter(
            f"Adapter returned rule missing fields: {', '.join(sorted(missing))}"
        )
    return rule


def _persist_rules(rules: List[Dict], dry_run: bool) -> Tuple[int, int]:
    if dry_run:
        with typer.progressbar(rules, label="Previewing rules"):
            pass
        return len(rules), 0

    inserted = 0
    updated = 0
    with storage.get_connection() as conn:
        with typer.progressbar(rules, label="Syncing rules") as iterator:
            for rule in iterator:
                exists = conn.execute(
                    "SELECT 1 FROM managed_rules WHERE vendor = ? AND rule_id = ?",
                    [rule["vendor"], rule["rule_id"]],
                ).fetchone()
                if exists:
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
                if exists:
                    updated += 1
                else:
                    inserted += 1
    return inserted, updated


def _print_summary(vendor: str, inserted: int, updated: int, job_id: str, dry_run: bool) -> None:
    typer.echo("")
    typer.echo("Rule Sync Summary")
    typer.echo("-----------------")
    typer.echo(f"Vendor: {vendor}")
    typer.echo(f"Inserted: {inserted}")
    typer.echo(f"Updated: {updated}")
    typer.echo(f"Job Reference: {job_id}{' (dry run)' if dry_run else ''}")


if __name__ == "__main__":
    typer.run(main)

