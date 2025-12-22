# Story 1.4: Sample Data Loader

Status: drafted

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

- [ ] Implement `scripts/seed_sample_data.py` (AC: 1,4)  
  - [ ] Read sample CSV, insert/update rows via `duckdb` connection.  
  - [ ] Load Cloudflare JSON via existing adapter (`scripts/rule_sync/cloudflare.py`).  
  - [ ] Print status lines (counts, success).  
- [ ] Handle idempotency (AC: 2)  
  - [ ] Use `INSERT OR REPLACE` or delete existing sample rows before insert.  
  - [ ] Ensure rule IDs serve as natural keys.  
- [ ] Hook into UI flow (AC: 3)  
  - [ ] After seeding, print “Run `streamlit run ui/app.py`” or trigger a Session State refresh (if executed via Streamlit button).  
  - [ ] Optionally expose a Streamlit button that calls the script via subprocess for non-CLI users.

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

<!-- story-context XML placeholder -->

### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

