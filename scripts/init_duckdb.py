#!/usr/bin/env python3
from __future__ import annotations

"""
Bootstrap the DuckDB warehouse with required tables.

Usage:
    python scripts/init_duckdb.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services import storage


def main() -> int:
    try:
        stats = storage.initialize_schema()
    except Exception as exc:  # pragma: no cover - surfaced to CLI
        print(f"❌ Failed to initialize DuckDB: {exc}", file=sys.stderr)
        return 1

    print("✅ DuckDB warehouse is ready.")
    for table, count in stats.items():
        print(f"   • {table}: {count} rows")
    print("Next steps: seed sample data or run CLIs under scripts/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


