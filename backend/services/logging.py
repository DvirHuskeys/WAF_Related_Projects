from __future__ import annotations

import logging
import os
import uuid
from typing import Optional

from backend.services import storage

LOGGER = logging.getLogger(__name__)


def logging_disabled() -> bool:
    return os.getenv("DISABLE_PERSONA_LOGGING", "0").lower() in {"1", "true", "yes"}


def log_persona_usage(
    persona_id: str,
    domain: str,
    action: str,
    channel: str,
    notes: Optional[str] = None,
) -> bool:
    if logging_disabled():
        return False

    try:
        with storage.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO persona_usage (id, persona_id, domain, action, channel, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    str(uuid.uuid4()),
                    persona_id.lower(),
                    domain.lower(),
                    action,
                    channel,
                    notes,
                ],
            )
        return True
    except Exception as exc:  # pragma: no cover - best effort logging
        LOGGER.warning("Failed to log persona usage: %s", exc)
        return False












