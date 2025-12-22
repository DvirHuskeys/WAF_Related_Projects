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

