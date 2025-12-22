from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from backend.services import activity, storage


def _author_name() -> str:
    return os.getenv("ANNOTATION_AUTHOR") or os.getenv("USER", "security-team")


def _current_role() -> str:
    return os.getenv("ROLE", "admin")


def list_notes(vendor: str, rule_id: str, limit: int = 20) -> List[Dict]:
    with storage.get_connection() as conn:
        rows = conn.execute(
            """
            SELECT note_id, rule_vendor, rule_id, author, content, created_at, updated_at
            FROM rule_notes
            WHERE rule_vendor = ? AND rule_id = ? AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT ?
            """,
            [vendor, rule_id, limit],
        ).fetchall()
        columns = [desc[0] for desc in conn.description]
    return [dict(zip(columns, row)) for row in rows]


def _get_note(note_id: str) -> Optional[Dict]:
    with storage.get_connection() as conn:
        rows = conn.execute(
            """
            SELECT note_id, rule_vendor, rule_id, author, content, created_at, updated_at, deleted_at
            FROM rule_notes
            WHERE note_id = ?
            """,
            [note_id],
        ).fetchall()
        columns = [desc[0] for desc in conn.description]
    if not rows:
        return None
    return dict(zip(columns, rows[0]))


def can_edit(note: Dict, actor: Optional[str] = None) -> bool:
    author = actor or _author_name()
    return note.get("author") == author or _current_role() == "admin"


def add_note(vendor: str, rule_id: str, content: str, author: Optional[str] = None) -> str:
    author_name = author or _author_name()
    note_id = f"note-{uuid.uuid4().hex}"
    with storage.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO rule_notes (note_id, rule_vendor, rule_id, author, content)
            VALUES (?, ?, ?, ?, ?)
            """,
            [note_id, vendor, rule_id, author_name, content.strip()],
        )
    activity.log_activity(
        "rule_note.add",
        f"{vendor}:{rule_id}",
        author_name,
        details={"note_id": note_id},
    )
    return note_id


def update_note(note_id: str, content: str, author: Optional[str] = None) -> bool:
    note = _get_note(note_id)
    if not note or note.get("deleted_at"):
        return False
    author_name = author or _author_name()
    if not can_edit(note, author_name):
        activity.log_activity(
            "rule_note.edit_denied",
            f"{note['rule_vendor']}:{note['rule_id']}",
            author_name,
            details={"note_id": note_id},
            status="denied",
        )
        return False
    with storage.get_connection() as conn:
        conn.execute(
            """
            UPDATE rule_notes
            SET content = ?, updated_at = ?
            WHERE note_id = ?
            """,
            [content.strip(), datetime.now(timezone.utc).isoformat(), note_id],
        )
    activity.log_activity(
        "rule_note.edit",
        f"{note['rule_vendor']}:{note['rule_id']}",
        author_name,
        details={"note_id": note_id},
    )
    return True


def delete_note(note_id: str, author: Optional[str] = None) -> bool:
    note = _get_note(note_id)
    if not note or note.get("deleted_at"):
        return False
    author_name = author or _author_name()
    if not can_edit(note, author_name):
        activity.log_activity(
            "rule_note.delete_denied",
            f"{note['rule_vendor']}:{note['rule_id']}",
            author_name,
            details={"note_id": note_id},
            status="denied",
        )
        return False
    with storage.get_connection() as conn:
        conn.execute(
            """
            UPDATE rule_notes
            SET deleted_at = ?
            WHERE note_id = ?
            """,
            [datetime.now(timezone.utc).isoformat(), note_id],
        )
    activity.log_activity(
        "rule_note.delete",
        f"{note['rule_vendor']}:{note['rule_id']}",
        author_name,
        details={"note_id": note_id},
    )
    return True


def author_label() -> str:
    return _author_name()











