import json

from backend.services import storage


def test_tables_exist(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "WAREHOUSE_PATH", tmp_path / "warehouse.db")
    with storage.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO domain_enrichment VALUES (
                'example.com','cloudflare','cloudflare',
                0.7,0.6,0.5,CURRENT_TIMESTAMP,'{}'
            )
            """
        )
        rows = conn.execute("SELECT COUNT(*) FROM domain_enrichment").fetchone()
    assert rows[0] == 1


def test_initialize_schema_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "WAREHOUSE_PATH", tmp_path / "warehouse.db")
    first = storage.initialize_schema()
    second = storage.initialize_schema()
    expected = {
        "domain_enrichment": 0,
        "managed_rules": 0,
        "job_runs": 0,
        "persona_usage": 0,
        "rule_notes": 0,
        "activity_log": 0,
    }
    assert first == second == expected
    assert storage.WAREHOUSE_PATH.exists()


def test_list_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "WAREHOUSE_PATH", tmp_path / "warehouse.db")
    storage.initialize_schema()
    with storage.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO managed_rules (
                vendor, rule_id, name, category,
                detection_pattern, mitigation, severity,
                metadata, source, synced_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                "cloudflare",
                "100",
                "SQLi Shield",
                "injection",
                "expr",
                "block",
                "high",
                json.dumps({"synced_at": "2025-01-01T00:00:00Z"}),
                "cloudflare_export",
                "2025-01-01T00:00:00Z",
            ],
        )
    rules = storage.list_rules()
    assert len(rules) == 1
    assert rules[0]["vendor"] == "cloudflare"
    assert rules[0]["rule_id"] == "100"
    assert rules[0]["detection_pattern"] == "expr"
    assert rules[0]["mitigation"] == "block"

