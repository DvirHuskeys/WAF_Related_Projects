# Story 2.6: Data Export Utilities

Status: review

## Story

As an analyst,  
I want to export enriched domains and rule libraries as CSV/Parquet,  
so I can explore the data in notebooks or share snapshots without giving direct DB access.

## Acceptance Criteria

1. Given enrichment data exists, when I click “Download Domains CSV” (or run `python scripts/export_data.py --domains`) then a file is saved under `exports/` with ISO timestamp in the filename and headers matching the DuckDB schema.  
2. Same export command supports `--parquet` option for domains and rules; Parquet files include schema metadata.  
3. Streamlit UI exposes download buttons for domains and rules that call the same helper, displaying success/error toasts.  
4. Exports respect freshness warnings (append note if data older than SLA) and include a footer referencing the job ID from Story 2.4.  
5. README documents how to export manually via CLI.

## Tasks / Subtasks

- [x] Export helper (AC: 1–2)  
  - [x] Implemented `backend/services/export.py` with domain/rule exporters (CSV & Parquet) adding `stale_warning`.  
- [x] CLI wiring (AC: 1–2 & 5)  
  - [x] Added `scripts/export_data.py` + Makefile targets + README docs.  
- [x] Streamlit buttons (AC: 3 & 4)  
  - [x] UI now offers buttons for domains/rules CSV/Parquet and displays job references + footnotes.  
- [x] Tests / verification  
  - [x] Added `tests/test_export.py`; manual runs confirm files saved under `exports/`.

## Dev Notes

- Aligns with PRD FR18; export path should be configurable via env.  
- Consider cleaning up old exports (optional).  
- Use same is_stale helper from Story 2.5.

### Project Structure Notes

- New folder `exports/` should be gitignored but created by script if missing.  
- Keep CLI naming consistent with other scripts.

### References

- [Source: docs/epics.md#story-26-data-export-utilities]  
- [Source: docs/prd.md#functional-requirements FR18]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/2-6-data-export-utilities.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Added export helpers + Typer CLI + Streamlit buttons, wired to job logging & freshness warnings.  
- 2025-11-30: README/.env/Makefile updated; tests cover CSV/Parquet outputs.  
- 2025-11-30: `make test` (12 passed).

### Completion Notes List

- Exports now share a centralized helper that writes CSV/Parquet, annotates stale data, and records job IDs with optional footnotes.  
- Streamlit UI surfaces the same flows with success/error messaging.  
- CLI + Makefile provide reproducible commands for automation.

### File List

- `backend/services/export.py`
- `scripts/export_data.py`
- `ui/app.py`
- `tests/test_export.py`
- `.env.example`
- `README.md`
- `Makefile`
- `.gitignore`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Implemented CSV/Parquet export utilities across CLI and UI; story ready for review.
