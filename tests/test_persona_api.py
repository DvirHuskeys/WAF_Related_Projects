from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.main import app
from backend.services import storage


def _setup(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, "WAREHOUSE_PATH", tmp_path / "warehouse.db")
    storage.initialize_schema()
    with storage.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO domain_enrichment VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            [
                "example.com",
                "cloudflare",
                "cloudflare",
                0.6,
                0.5,
                0.4,
                datetime.now(timezone.utc).isoformat(),
                "{}",
            ],
        )


def test_persona_view_success(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    client = TestClient(app)
    resp = client.get("/persona/ae/example.com")
    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "example.com"
    assert "story_prompt" in data
    assert data["hooks"]


def test_persona_view_invalid_persona(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    client = TestClient(app)
    resp = client.get("/persona/unknown/example.com")
    assert resp.status_code == 400


def test_persona_view_missing_domain(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    client = TestClient(app)
    resp = client.get("/persona/ae/missing.com")
    assert resp.status_code == 404


