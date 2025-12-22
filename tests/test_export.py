import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.services import export, jobs, rules, storage


def _setup_db(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "WAREHOUSE_PATH", tmp_path / "warehouse.db")
    storage.initialize_schema()


def test_export_domains_csv(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
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
                (datetime.now(timezone.utc) - timedelta(days=40)).isoformat(),
                "{}",
            ],
        )
    result = export.export_domains(fmt="csv", output_dir=tmp_path)
    assert result.path.exists()
    content = result.path.read_text()
    assert "example.com" in content
    # Expect stale warning column
    assert "stale_warning" in content.splitlines()[0]
    assert result.footnote_path and result.footnote_path.exists()


def test_export_rules_parquet(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
    metadata = {"synced_at": (datetime.now(timezone.utc)).isoformat()}
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
                "1000",
                "Rule",
                "bot",
                "expr",
                "block",
                "high",
                json.dumps(metadata),
                "cloudflare_export",
                metadata["synced_at"],
            ],
        )
    result = export.export_rules(fmt="parquet", output_dir=tmp_path)
    assert result.path.exists()
    # Parquet file should have non-zero size
    assert result.path.stat().st_size > 0


def test_export_rules_includes_notes(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
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
                "1000",
                "Rule",
                "bot",
                "expr",
                "block",
                "high",
                json.dumps({"synced_at": "2025-01-01T00:00:00Z"}),
                "cloudflare_export",
                "2025-01-01T00:00:00Z",
            ],
        )
    monkeypatch.setenv("ANNOTATION_AUTHOR", "alice")
    rules.add_note("cloudflare", "1000", "Customer override note.")
    result = export.export_rules(fmt="csv", output_dir=tmp_path)
    contents = result.path.read_text()
    assert "notes" in contents.splitlines()[0]
    assert "Customer override note." in contents


def test_export_usage_csv(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
    with storage.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO persona_usage (id, persona_id, domain, action, channel, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ["1", "ae", "example.com", "copy", "UI", "initial test"],
        )
    result = export.export_usage(fmt="csv", output_dir=tmp_path)
    assert result.path.exists()
    contents = result.path.read_text()
    assert "persona_id" in contents.splitlines()[0]
    assert "example.com" in contents


def test_generate_radar_summary_markdown(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
    with storage.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO domain_enrichment VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                "example.com",
                "cloudflare",
                "fastly",
                0.72,
                0.55,
                0.48,
                datetime.now(timezone.utc).isoformat(),
                "{}",
            ],
        )
    monkeypatch.setattr(export, "REPORTS_DIR", tmp_path)
    result = export.generate_radar_summary("example.com", persona_id="ae")
    assert result.markdown_path.exists()
    contents = result.markdown_path.read_text()
    assert "example.com Radar Summary" in contents
    assert "Stack Snapshot" in contents
    assert result.job_id.startswith("radar_summary")
    assert result.pdf_path is None


def test_generate_radar_summary_pdf(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
    with storage.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO domain_enrichment VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                "acme.io",
                "aws_waf",
                "akamai",
                0.61,
                0.42,
                0.58,
                datetime.now(timezone.utc).isoformat(),
                "{}",
            ],
        )
    monkeypatch.setattr(export, "REPORTS_DIR", tmp_path)
    result = export.generate_radar_summary("acme.io", persona_id="ae", create_pdf=True)
    assert result.pdf_path is not None
    assert result.pdf_path.exists()
    assert result.pdf_path.suffix == ".pdf"


def test_generate_rule_brief_markdown(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
    now = datetime.now(timezone.utc).isoformat()
    with storage.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO managed_rules (
                vendor, rule_id, name, category,
                detection_pattern, mitigation, severity,
                metadata, source, synced_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                "cloudflare",
                "1000",
                "Bot Fight",
                "bot",
                "expr_a",
                "block",
                "high",
                json.dumps({"synced_at": now}),
                "cloudflare_export",
                now,
            ],
        )
        conn.execute(
            """
            INSERT INTO managed_rules (
                vendor, rule_id, name, category,
                detection_pattern, mitigation, severity,
                metadata, source, synced_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                "aws_waf",
                "2000",
                "SQLi Shield",
                "injection",
                "expr_b",
                "challenge",
                "medium",
                json.dumps({"synced_at": now}),
                "aws_export",
                now,
            ],
        )
        conn.execute(
            """
            INSERT INTO rule_notes (note_id, rule_vendor, rule_id, author, content)
            VALUES (?, ?, ?, ?, ?)
            """,
            ["note-1", "cloudflare", "1000", "alice", "Customer A overrides thresholds."],
        )
    job_id = jobs.start_job("rule_sync", {"vendor": "cloudflare"})
    jobs.complete_job(job_id, "success", {"vendor": "cloudflare"})
    monkeypatch.setattr(export, "REPORTS_DIR", tmp_path)
    result = export.generate_rule_brief(
        "acme.io",
        ("cloudflare", "1000"),
        ("aws_waf", "2000"),
    )
    assert result.markdown_path.exists()
    contents = result.markdown_path.read_text()
    assert "acme.io Rule Transparency Brief" in contents
    assert "Rule Sync Job" in contents
    assert "Customer A overrides thresholds." in contents


def test_generate_rule_brief_pdf(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
    now = datetime.now(timezone.utc).isoformat()
    with storage.get_connection() as conn:
        for vendor, rule_id in [("cloudflare", "1000"), ("aws_waf", "2000")]:
            conn.execute(
                """
                INSERT INTO managed_rules (
                    vendor, rule_id, name, category,
                    detection_pattern, mitigation, severity,
                    metadata, source, synced_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    vendor,
                    rule_id,
                    f"{vendor}-rule",
                    "bot",
                    "expr",
                    "block",
                    "medium",
                    json.dumps({"synced_at": now}),
                    f"{vendor}_export",
                    now,
                ],
            )
    monkeypatch.setattr(export, "REPORTS_DIR", tmp_path)
    result = export.generate_rule_brief(
        "zenith.io",
        ("cloudflare", "1000"),
        ("aws_waf", "2000"),
        create_pdf=True,
    )
    assert result.pdf_path is not None
    assert result.pdf_path.exists()
    assert result.pdf_path.suffix == ".pdf"

