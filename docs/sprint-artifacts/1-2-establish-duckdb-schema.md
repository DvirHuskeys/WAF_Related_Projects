# Story 1.2: Establish DuckDB Schema

Status: review

## Story

As a developer,  
I want a repeatable script that creates the DuckDB database and required tables,  
so that enrichment and rule-sync jobs can persist records without manual SQL.

## Acceptance Criteria

1. Given I run `python scripts/init_duckdb.py` (or the equivalent storage helper), when `data/warehouse.db` does not exist, then tables `domain_enrichment` and `managed_rules` are created with the columns defined in the PRD (including JSON fields).  
2. Re-running the script is idempotent: schema creation does not fail if the database or tables already exist.  
3. The script prints success/failure messaging and exits non‑zero on fatal errors; docs/README reference the command.  
4. JSON support is enabled in DuckDB so `raw` and `metadata` columns accept structured content.

## Tasks / Subtasks

- [x] Implement `scripts/init_duckdb.py` (AC: 1,4)  
  - [x] Use `duckdb.connect("data/warehouse.db")` and execute the CREATE TABLE statements from PRD.  
  - [x] Enable JSON extension (`INSTALL/LOAD json`) before creating tables.  
- [x] Make migration idempotent (AC: 2)  
  - [x] Wrap CREATE statements with `CREATE TABLE IF NOT EXISTS` or check catalog before creation.  
  - [x] Add sanity check query that prints table counts after creation.  
- [x] Developer ergonomics (AC: 3)  
  - [x] Document the command in README/Makefile.  
  - [x] Emit clear console output (success + next steps).

## Dev Notes

- Aligns with architecture goal of keeping everything local-first (`docs/architecture.md#1-project-context--goals`).  
- Schema definitions come straight from `docs/prd.md#functional-requirements` → Intelligence Harvesting & Rule Transparency sections.  
- Script should live under `scripts/` per project structure established in Story 1.1; reuse the same virtualenv instructions.  
- Future epics (radar, persona) depend on these tables, so include simple validation query (e.g., `duckdb.sql("DESCRIBE domain_enrichment")`) after creation.

### Project Structure Notes

- Place the script in `scripts/` and update the root README/Makefile created in Story 1.1 so the bootstrap sequence becomes: create venv → run `init_duckdb.py` → seed sample data.  
- Ensure `backend/services/storage.py` exposes helper functions that the CLI and Streamlit UI can reuse (avoid duplicate SQL). No path conflicts detected.

### References

- [Source: docs/epics.md#epic-1-foundation-sandbox--data-layer]  
- [Source: docs/prd.md#functional-requirements]  
- [Source: docs/architecture.md#5-data-model-snapshot-duckdb]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/1-2-establish-duckdb-schema.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Added JSON extension loading + `initialize_schema()` helper inside `backend/services/storage.py` so app code and CLI share the same bootstrap logic.
- 2025-11-30: Authored `scripts/init_duckdb.py`, wired it into `make init-db`, and ran it locally to confirm success output (row counts + next-step guidance).
- 2025-11-30: Updated README bootstrap instructions, added the Makefile target, and expanded `tests/test_schema.py` to cover idempotent initialization; finished with `make test`.

### Completion Notes List

- `scripts/init_duckdb.py` now installs/loads the JSON extension, creates tables via `storage.initialize_schema()`, and reports row counts.
- README/Makefile instruct devs to run `make init-db`, keeping the bootstrap workflow in sync with Story 1.1.
- Regression coverage includes the new schema initializer test and a full `make test` run.

### File List

- `backend/services/storage.py`
- `scripts/init_duckdb.py`
- `Makefile`
- `README.md`
- `tests/test_schema.py`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Implemented DuckDB initialization script, documentation updates, and schema regression tests; story marked ready for review.
