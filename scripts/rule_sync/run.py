from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Callable, Dict, List

import typer

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from backend.services import storage

VENDOR_LOADERS: Dict[str, str] = {
    "cloudflare": "scripts.rule_sync.cloudflare",
}


def main(
    vendor: str = typer.Argument(..., help="Vendor id (e.g. cloudflare)"),
    source: Path = typer.Option(
        Path("data/rules/cloudflare_sample.json"),
        help="Path to vendor rule export",
    ),
):
    vendor = vendor.lower()
    if vendor not in VENDOR_LOADERS:
        raise typer.BadParameter(f"Unsupported vendor '{vendor}'.")

    loader = _resolve_loader(VENDOR_LOADERS[vendor])
    rules = loader(source)
    with storage.get_connection() as conn:
        conn.executemany(
            """
            INSERT INTO managed_rules VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            [
                (
                    rule["vendor"],
                    rule["rule_id"],
                    rule["name"],
                    rule["category"],
                    rule["detection_pattern"],
                    rule["mitigation"],
                    rule["severity"],
                    rule["metadata"],
                )
                for rule in rules
            ],
        )
    typer.secho(f"[+] Loaded {len(rules)} {vendor} rules", fg=typer.colors.GREEN)


def _resolve_loader(path: str) -> Callable[[Path], List[dict]]:
    module_name, func_name = path, "load_rules"
    module = importlib.import_module(module_name)
    loader = getattr(module, func_name, None)
    if not loader:
        raise typer.BadParameter(f"{module_name}.{func_name} not found")
    return loader


if __name__ == "__main__":
    typer.run(main)

