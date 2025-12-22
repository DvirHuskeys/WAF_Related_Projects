from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List


def load_rules(source: Path) -> List[dict]:
    with source.open() as handle:
        raw = json.load(handle)
    rules = []
    for entry in raw:
        rules.append(
            {
                "vendor": "cloudflare",
                "rule_id": entry["id"],
                "name": entry["name"],
                "category": entry.get("category", "general"),
                "detection_pattern": entry.get("expression", ""),
                "mitigation": entry.get("action", "log"),
                "severity": entry.get("severity", "medium"),
                "metadata": json.dumps(entry),
                "source": entry.get("source", f"cloudflare_export:{source.name}"),
                "synced_at": entry.get("synced_at")
                or datetime.now(timezone.utc).isoformat(),
            }
        )
    return rules

