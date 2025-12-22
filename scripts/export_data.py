#!/usr/bin/env python3
from __future__ import annotations

import typer

from backend.services import export

app = typer.Typer(add_completion=False)


@app.command()
def main(
    domains: bool = typer.Option(False, "--domains", help="Export domain data"),
    rules: bool = typer.Option(False, "--rules", help="Export managed rules"),
    usage: bool = typer.Option(False, "--usage", help="Export persona usage logs"),
    fmt: str = typer.Option("csv", "--format", help="csv or parquet"),
) -> None:
    selected = sum([domains, rules, usage])
    if selected != 1:
        raise typer.BadParameter("Select exactly one of --domains/--rules/--usage.")

    if domains:
        target = export.export_domains
    elif rules:
        target = export.export_rules
    else:
        target = export.export_usage

    result = target(fmt=fmt)
    typer.secho(
        f"[+] Export complete: {result.path} (Job {result.job_id})", fg=typer.colors.GREEN
    )
    if result.footnote_path:
        typer.echo(f"Notes written to {result.footnote_path}")


if __name__ == "__main__":
    app()


