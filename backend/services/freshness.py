from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

DEFAULT_THRESHOLD_DAYS = int(os.getenv("STALE_THRESHOLD_DAYS", "30"))


def _parse_timestamp(value: Optional[object]) -> Optional[datetime]:
    if value is None:
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


def is_stale(
    timestamp: Optional[object], threshold_days: Optional[int] = None
) -> Tuple[bool, Optional[int]]:
    dt = _parse_timestamp(timestamp)
    if not dt:
        return True, None
    threshold = threshold_days or DEFAULT_THRESHOLD_DAYS
    delta_days = (datetime.now(timezone.utc) - dt).days
    return delta_days >= threshold, delta_days


def get_warning(
    timestamp: Optional[object],
    label: str = "Data",
    threshold_days: Optional[int] = None,
) -> Optional[str]:
    stale, days = is_stale(timestamp, threshold_days)
    if not stale:
        return None
    if days is None:
        return f"{label} freshness unknown - re-run enrichment"
    return f"{label} {days}d old - re-run enrichment"


