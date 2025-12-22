# Story 1.4: Sample Data Loader

Status: review

## Story

As a developer,  
I want a script that seeds demo domains and Cloudflare rule entries into DuckDB,  
so that anyone can demo the Streamlit UI without running the full enrichment pipeline.

## Acceptance Criteria

1. Given sample files (`data/samples/domains.csv`, `data/rules/cloudflare_sample.json`) exist, when I run `python scripts/seed_sample_data.py`, then DuckDB `domain_enrichment` includes at least four rows and `managed_rules` includes at least two rows matching the samples.  
2. Re-running the script upserts data (no duplicate domains/rules).  
3. After seeding, the Streamlit UI automatically refreshes (or prints a reminder) to display the seeded rows.  
4. Script logs each step (loading CSV, syncing rules) and exits non-zero on failure.

## Tasks / Subtasks

- [x] Implement `scripts/seed_sample_data.py` (AC: 1,4)  
  - [x] Read sample CSV, insert/update rows via `duckdb` connection.  
  - [x] Load Cloudflare JSON via existing adapter (`scripts/rule_sync/cloudflare.py`).  
  - [x] Print status lines (counts, success).  
- [x] Handle idempotency (AC: 2)  
  - [x] Use targeted deletes before insert so domains/rules stay unique.  
  - [x] Ensure rule IDs serve as natural keys.  
- [x] Hook into UI flow (AC: 3)  
  - [x] After seeding, print “Run `streamlit run ui/app.py`” to refresh UI.  
  - [x] Added `make seed-sample-data` target for non-CLI users.

## Dev Notes

- Reuses logic from Stories 2.1–2.3 but with fixed sample files to keep the demo deterministic.  
- Consider adding a `--reset` flag to wipe data clean.  
- Keeps project aligned with local-first architecture (no network calls).

### Project Structure Notes

- Place script in `scripts/` alongside enrichment/rule-sync CLIs; follow existing Typer pattern if desired.  
- Update README/Makefile with `make seed-sample-data` convenience target.

### References

- [Source: docs/epics.md#story-14-sample-data-loader]  
- [Source: docs/prd.md#functional-requirements] (FR1–FR4 foundation)

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/1-4-sample-data-loader.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Built `scripts/seed_sample_data.py` using storage helpers + Cloudflare adapter; includes logging, `--reset`, and deterministic payloads for domains/rules.
- 2025-11-30: Added `make seed-sample-data` + README instructions so users can seed data without remembering the script path; CLI prints reminders to launch Streamlit (AC3).
- 2025-11-30: Verified seeding + regression suite via `python scripts/seed_sample_data.py --reset` and `make test`.

### Completion Notes List

- Sample loader seeds four domains/two rules from repo fixtures, logs each step, and exits non-zero on failure; repeat runs stay idempotent via targeted deletes.
- README + Makefile document the new workflow step, keeping bootstrapping simple for demos.
- Tests remain green; manual runs confirm Streamlit sees seeded data immediately.

### File List

- `scripts/seed_sample_data.py`
- `Makefile`
- `README.md`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Implemented deterministic sample data loader + documentation updates; story ready for review.
