# Story 2.4: Enrichment Status & CLI Flags

Status: review

## Story

As an operator,  
I want enrichment and rule-sync CLIs to report progress, log runs, and support standard flags,  
so I can monitor jobs and troubleshoot failures without rerunning everything.

## Acceptance Criteria

1. Each CLI (domain enrichment and rule sync) prints a Rich/Typer progress display showing current domain/vendor and overall counts; fatal errors exit non-zero with clear messaging.  
2. Both CLIs support shared flags: `--limit`, `--vendor`, `--source`, `--dry-run` (where applicable). Invalid flag combinations raise helpful errors.  
3. CLI creates/updates a `job_runs` DuckDB table with columns: `job_id`, `job_type` (enrich/rule_sync), `started_at`, `finished_at`, `status`, `details` (JSON).  
4. On completion (success or failure), CLI prints “Job recorded as <job_id>” so operators can inspect the log later.  
5. README/Makefile mention the available flags and describe where job logs are stored.

## Tasks / Subtasks

- [x] Progress output (AC: 1)  
  - [x] Integrated Typer progress bars into enrichment & rule sync CLIs.  
  - [x] Logging stays concise even with `--limit`/`--dry-run`.  
- [x] Flag wiring (AC: 2)  
  - [x] Domain CLI already had `--limit/--dry-run`; Rule Sync now supports `--dry-run` and vendor/source options documented.  
- [x] Job logging (AC: 3)  
  - [x] `job_runs` table created via storage initializer plus helper functions (`backend/services/jobs.py`).  
  - [x] CLIs record start/finish with JSON details.  
- [x] Docs (AC: 4–5)  
  - [x] README/Makefile updated with flag descriptions + log location.  
  - [x] CLIs print “Job Reference: ...” upon completion.

## Dev Notes

- Leverage existing DuckDB connection helper; consider context manager for logging start/end.  
- `details` JSON can store counts (processed, inserted, skipped).  
- Keep CLI defaults minimal so local dev isn’t overwhelmed.

### Project Structure Notes

- Job logging helpers could live in `backend/services/jobs.py`; both CLIs import shared utilities.  
- Ensure script names stay snake_case and Typer apps remain in `scripts/`.

### References

- [Source: docs/epics.md#story-24-enrichment-status--cli-flags]  
- [Source: docs/prd.md#functional-requirements FR4, FR21]  
- [Source: docs/architecture.md#6-operational-notes]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/2-4-enrichment-status-cli-flags.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Added `backend/services/jobs.py` with helpers + schema updates to track job runs.  
- 2025-11-30: Refactored enrichment and rule-sync CLIs to show progress, honor shared flags, and emit job summaries.  
- 2025-11-30: README/Makefile document usage; manual smoke runs + `make test`.

### Completion Notes List

- Both CLIs now record job ids, print summaries, and support dry-run/progress experiences per ACs.  
- Job logs persist counts + errors in DuckDB (`job_runs`), enabling future inspection.  
- Documentation & automation targets describe available flags.

### File List

- `backend/services/jobs.py`
- `backend/services/storage.py`
- `scripts/domain_enrich.py`
- `scripts/rule_sync/run.py`
- `README.md`
- `Makefile`
- `tests/test_jobs.py`
- `tests/test_rule_sync.py`
- `docs/adapters.md`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Implemented job logging, progress output, shared flags, and documentation updates for CLIs; story ready for review.
