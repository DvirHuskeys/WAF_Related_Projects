from __future__ import annotations

import json
import os
import uuid
from typing import Dict, Optional

from backend.services import storage


def _current_role() -> str:
    return os.getenv("ROLE", "admin")


def log_activity(
    action: str,
    target: str,
    author: str,
    details: Optional[Dict] = None,
    status: str = "success",
):
    entry_id = f"act-{uuid.uuid4().hex}"
    with storage.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO activity_log (id, author, role, action, target, details, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                entry_id,
                author,
                _current_role(),
                action,
                target,
                json.dumps(details or {}),
                status,
            ],
        )
    return entry_id











