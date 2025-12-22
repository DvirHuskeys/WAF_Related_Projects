from backend.services import jobs, storage


def test_job_logging(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "WAREHOUSE_PATH", tmp_path / "warehouse.db")
    # initialize tables
    storage.initialize_schema()

    job_id = jobs.start_job("test", {"foo": "bar"})
    jobs.complete_job(job_id, "success", {"result": 1})

    with storage.get_connection() as conn:
        row = conn.execute(
            "SELECT status, details FROM job_runs WHERE job_id = ?", [job_id]
        ).fetchone()

    assert row[0] == "success"
    assert "result" in row[1]


def test_latest_job_returns_most_recent(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "WAREHOUSE_PATH", tmp_path / "warehouse.db")
    storage.initialize_schema()

    job_old = jobs.start_job("domain_enrich", {"foo": "old"})
    jobs.complete_job(job_old, "success", {"result": "first"})

    job_new = jobs.start_job("domain_enrich", {"foo": "new"})
    jobs.complete_job(job_new, "failed", {"error": "boom"})

    other = jobs.start_job("rules", {})
    jobs.complete_job(other, "success", {})

    record = jobs.latest_job("domain_enrich")
    assert record is not None
    assert record["job_id"] == job_new
    assert record["status"] == "failed"
    assert record["details"]["error"] == "boom"

