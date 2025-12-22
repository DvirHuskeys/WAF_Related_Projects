from backend.services import logging as usage_logging, storage


def _setup(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, "WAREHOUSE_PATH", tmp_path / "warehouse.db")
    storage.initialize_schema()


def test_log_persona_usage_inserts(monkeypatch, tmp_path):
    monkeypatch.delenv("DISABLE_PERSONA_LOGGING", raising=False)
    _setup(monkeypatch, tmp_path)
    logged = usage_logging.log_persona_usage("ae", "example.com", "view", "API")
    assert logged
    with storage.get_connection() as conn:
        rows = conn.execute(
            "SELECT persona_id, domain, action, channel FROM persona_usage"
        ).fetchall()
        assert rows == [("ae", "example.com", "view", "API")]


def test_log_persona_usage_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("DISABLE_PERSONA_LOGGING", "1")
    _setup(monkeypatch, tmp_path)
    logged = usage_logging.log_persona_usage("ae", "example.com", "copy", "UI")
    assert not logged
    with storage.get_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM persona_usage").fetchone()[0]
        assert count == 0











