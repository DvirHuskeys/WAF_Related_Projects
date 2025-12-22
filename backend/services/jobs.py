from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from backend.services import storage


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def start_job(job_type: str, details: Optional[Dict] = None) -> str:
    unique_suffix = uuid.uuid4().hex[:6]
    job_id = f"{job_type}-{_utcnow().strftime('%Y%m%d-%H%M%S')}-{unique_suffix}"
    payload = details or {}
    with storage.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO job_runs (job_id, job_type, started_at, status, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            [job_id, job_type, _utcnow(), "running", json.dumps(payload)],
        )
    return job_id


def complete_job(job_id: str, status: str, details: Optional[Dict] = None) -> None:
    payload = details or {}
    with storage.get_connection() as conn:
        conn.execute(
            """
            UPDATE job_runs
            SET finished_at = ?, status = ?, details = ?
            WHERE job_id = ?
            """,
            [_utcnow(), status, json.dumps(payload), job_id],
        )


def latest_job(job_type: str) -> Optional[Dict[str, Any]]:
    with storage.get_connection() as conn:
        row = conn.execute(
            """
            SELECT job_id, job_type, started_at, finished_at, status, details
            FROM job_runs
            WHERE job_type = ?
            ORDER BY started_at DESC
            LIMIT 1
            """,
            [job_type],
        ).fetchone()
        columns = [desc[0] for desc in conn.description] if row else []
    if not row:
        return None
    record = dict(zip(columns, row))
    details = record.get("details")
    if isinstance(details, str):
        try:
            record["details"] = json.loads(details)
        except json.JSONDecodeError:
            pass
    return record


