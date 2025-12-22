# Story 2.1: CSV Ingestion CLI

Status: drafted

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

- [ ] Implement Typer CLI (AC: 1–3)  
  - [ ] Parse CSV via `csv.DictReader`, strip whitespace, deduplicate.  
  - [ ] Validate domains (`urlparse` or regex).  
  - [ ] Handle `--limit` and `--dry-run`.  
- [ ] Integrate storage helper (AC: 1 & 2)  
  - [ ] Use `backend/services/storage.get_connection()` to insert rows.  
- [ ] Progress + summary (AC: 1 & 4)  
  - [ ] Use Rich/typer echo for progress; print summary counts.  
  - [ ] Emit warnings for skipped rows.  
- [ ] Update docs (AC: 5)  
  - [ ] README + Makefile entry describing command and flags.

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

<!-- story-context XML placeholder -->

### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

