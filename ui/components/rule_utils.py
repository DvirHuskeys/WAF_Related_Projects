from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional


def parse_rule_synced_at(
    synced_at: Optional[object], metadata: Optional[str] = None
) -> Optional[datetime]:
    dt = _coerce_timestamp(synced_at)
    if dt:
        return dt
    if not metadata:
        return None
    try:
        payload = json.loads(metadata)
    except Exception:
        return None
    value = payload.get("synced_at") or payload.get("updated_at")
    return _coerce_timestamp(value)


def _coerce_timestamp(value: Optional[object]) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt



