from __future__ import annotations

from pathlib import Path
from typing import Tuple

import typer

from backend.services import export as export_service

app = typer.Typer(help="Generate Rule Transparency briefs comparing two vendor rules.")


def _parse_identifier(value: str) -> Tuple[str, str]:
    if ":" not in value:
        raise typer.BadParameter("Rule identifier must be in vendor:rule_id format.")
    vendor, rule_id = value.split(":", 1)
    return vendor.strip(), rule_id.strip()


@app.command()
def main(
    domain: str = typer.Argument(..., help="Domain the brief applies to."),
    rule_a: str = typer.Argument(..., help="First rule (vendor:rule_id)."),
    rule_b: str = typer.Argument(..., help="Second rule (vendor:rule_id)."),
    output_dir: Path = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Optional override for docs/reports destination.",
    ),
    pdf: bool = typer.Option(
        False, "--pdf/--no-pdf", help="Also create a PDF alongside the Markdown."
    ),
    show: bool = typer.Option(
        False,
        "--show/--no-show",
        help="Print the rendered Markdown to stdout after export.",
    ),
):
    """Generate an executive-ready brief comparing two vendor rules."""
    vendor_a, rule_id_a = _parse_identifier(rule_a)
    vendor_b, rule_id_b = _parse_identifier(rule_b)
    result = export_service.generate_rule_brief(
        domain,
        (vendor_a, rule_id_a),
        (vendor_b, rule_id_b),
        output_dir=output_dir,
        create_pdf=pdf,
    )
    typer.echo(f"Markdown saved to {result.markdown_path}")
    if result.pdf_path:
        typer.echo(f"PDF saved to {result.pdf_path}")
    if show:
        typer.echo("\n--- Preview ---\n")
        typer.echo(result.preview)


if __name__ == "__main__":
    app()









