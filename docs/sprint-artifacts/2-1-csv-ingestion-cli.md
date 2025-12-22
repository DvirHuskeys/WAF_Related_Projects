# Story 2.1: CSV Ingestion CLI

Status: review

## Story

As an operations teammate,  
I want to run `python scripts/domain_enrich.py mylist.csv`,  
so that domain fingerprints populate DuckDB without touching code.

## Acceptance Criteria

1. Given a CSV with a `domain` header, when I run the command (with optional `--limit`) then rows are validated, progress is printed, and valid domains are inserted/updated in `domain_enrichment`.  
2. Invalid domains (empty, malformed, duplicates) are skipped with warning messages; CLI exits with non-zero code only for fatal errors (missing file, DuckDB failure).  
3. CLI supports `--dry-run` (shows what would change) and `--limit N` to cap processing for quick tests.  
4. After completion, CLI prints summary counts (processed, inserted, skipped) and references the job log entry (Story 2.4).  
5. Documentation (README/Makefile) lists the command and flags.

## Tasks / Subtasks

- [x] Implement Typer CLI (AC: 1–3)  
  - [x] Parse CSV via `csv.DictReader`, strip whitespace, deduplicate.  
  - [x] Validate domains via regex and respect `--limit` / `--dry-run`.  
- [x] Integrate storage helper (AC: 1 & 2)  
  - [x] Use `backend/services/storage.get_connection()` to insert rows with stack/scores.  
- [x] Progress + summary (AC: 1 & 4)  
  - [x] Echo progress per domain and print summary counts referencing a job id.  
  - [x] Emit warnings for skipped rows.  
- [x] Update docs (AC: 5)  
  - [x] README + Makefile entry describing command and flags.

## Dev Notes

- Align with architecture (#2 Data Model) so this CLI becomes the default ingestion path before any automation exists.  
- Reuse fingerprinting helper from Story 2.2 (call `fingerprint.detect_stack`).  
- Keep network calls optional (respect `USE_WAFW00F` flag); offline fallback still writes random heuristics.

### Project Structure Notes

- Place in `scripts/` next to seed/init scripts.  
- Provide entry point in README and `Makefile` target `run-domain-enrich`.  
- No conflicting modules detected.

### References

- [Source: docs/epics.md#story-21-csv-ingestion-cli]  
- [Source: docs/prd.md#functional-requirements FR1, FR21]  
- [Source: docs/architecture.md#2-architecture-overview]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/2-1-csv-ingestion-cli.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Rebuilt `scripts/domain_enrich.py` into a Typer CLI with validation, `--limit`, `--dry-run`, and job summary logging.
- 2025-11-30: Added helper functions/tests for domain validation & CSV loading, plus new Makefile target and README docs.
- 2025-11-30: Verified `python scripts/domain_enrich.py data/samples/domains.csv --dry-run` and a real ingestion run; finished with `make test`.

### Completion Notes List

- CLI now skips invalid/duplicate domains with warnings, supports dry runs, and prints job references + next steps.
- README documents command usage and `make domain-enrich` shortcut; bootstrap flow includes the new step.
- Added regression tests for domain validation and CSV parsing.

### File List

- `scripts/domain_enrich.py`
- `tests/test_domain_enrich.py`
- `README.md`
- `Makefile`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Implemented CSV ingestion CLI improvements plus docs/tests; story ready for review.
