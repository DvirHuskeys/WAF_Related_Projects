# Story 3.3: Persona Usage Logging

Status: review

## Story

As RevOps,  
I want to know which personas and domains are being copied or accessed,  
so I can measure adoption and prove that GTM teams are leveraging the insights.

## Acceptance Criteria

1. Whenever a persona card “Copy story” button is clicked or the persona API is called with `include_usage=true`, a `persona_usage` table row is written (columns: `id`, `timestamp`, `persona_id`, `domain`, `channel` [UI/API], `action` [view/copy], optional `notes`).  
2. Logging can be disabled via env flag `DISABLE_PERSONA_LOGGING=1` for privacy-sensitive sessions; default is enabled.  
3. CLI/Streamlit provide an “Export usage log” option that writes CSV/Parquet under `exports/` similar to Story 2.6.  
4. README documents how to view/reset usage logs and references the env toggle.  
5. Logging is lightweight (no blocking UI); failures are logged but don’t break persona rendering.

## Tasks / Subtasks

- [x] Table + helper (AC: 1 & 5)  
  - [x] DuckDB schema now creates `persona_usage`; helper `backend/services/logging.py` writes rows with env guard + best-effort handling.  
- [x] Integrate with UI/API (AC: 1–2)  
  - [x] FastAPI `/persona/...` logs views by default (toggle via `?log_usage=false` or `include_usage=false`), respects env flag.  
  - [x] Streamlit “Copy Story Prompt” button triggers usage logging without blocking UI.  
- [x] Export path (AC: 3)  
  - [x] `backend/services/export.py`/CLI/Streamlit buttons support usage CSV/Parquet + Makefile target.  
- [x] Docs (AC: 4)  
  - [x] README + `.env.example` document `DISABLE_PERSONA_LOGGING`, viewing/resetting logs, and export commands.

## Dev Notes

- Aligns with FR7 + FR18.  
- Consider hashing domain if privacy requires it later.  
- Keep job logging separate (Story 2.4) vs persona usage logs.

### Project Structure Notes

- Logging helper in `backend/services/logging.py`; import from both UI and API modules.  
- Table lives alongside `job_runs`, `domain_enrichment`, `managed_rules`.

### References

- [Source: docs/epics.md#story-33-persona-usage-logging]  
- [Source: docs/prd.md#functional-requirements FR7, FR18]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/3-3-persona-usage-logging.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Added `persona_usage` DuckDB table + logging helper guarded by env toggle.  
- 2025-11-30: Wired FastAPI + Streamlit copy button to log usage, extended exports/UI/CLI to cover usage data.  
- 2025-11-30: README/.env updated; tests cover logging + usage exports; `make test` (18 passed).

### Completion Notes List

- Persona interactions now write lightweight audit records with channel/action metadata while respecting privacy toggles.  
- Usage logs can be exported via CLI, Makefile, or UI and inspected/reset through documented DuckDB commands.  
- Failures during logging are swallowed with warnings, keeping the UX responsive.

### File List

- `backend/services/storage.py`
- `backend/services/logging.py`
- `backend/services/persona.py`
- `backend/services/export.py`
- `backend/main.py`
- `ui/app.py`
- `scripts/export_data.py`
- `Makefile`
- `.env.example`
- `README.md`
- `requirements.txt`
- `config/persona_hooks.yaml`
- `tests/test_schema.py`
- `tests/test_logging.py`
- `tests/test_export.py`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Implemented persona usage logging across API/UI with exports, env toggle, and documentation.
