from __future__ import annotations

from pathlib import Path

import typer

from backend.services import export as export_service

app = typer.Typer(help="Generate GTM Radar one-pager exports.")


@app.command()
def main(
    domain: str = typer.Argument(..., help="Domain to summarize."),
    persona: str = typer.Option(
        "ae", "--persona", "-p", help="Persona ID to tailor the hooks."
    ),
    output_dir: Path = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Override destination directory (default docs/reports).",
    ),
    pdf: bool = typer.Option(
        False, "--pdf/--no-pdf", help="Also create a PDF alongside the Markdown."
    ),
    show: bool = typer.Option(
        False,
        "--show/--no-show",
        help="Print the rendered Markdown to stdout for quick inspection.",
    ),
):
    """Generate a radar summary export for the requested domain."""
    result = export_service.generate_radar_summary(
        domain,
        persona_id=persona,
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









