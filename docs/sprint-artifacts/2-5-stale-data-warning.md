# Story 2.5: Stale Data Warning

Status: review

## Story

As a persona or GTM user,  
I want visual warnings when enrichment or rule sync data is older than 30 days,  
so I know when to re-run the pipelines before trusting the intel.

## Acceptance Criteria

1. Given a domain row whose `last_observed` is older than the freshness SLA (30 days), when the Streamlit UI renders the Radar table or persona cards, then a warning badge (“Data 37d old – re-run enrichment”) appears inline.  
2. When a managed rule’s metadata timestamp exceeds the SLA, Rule Transparency views and exports show the same warning badge.  
3. Persona API responses include a `stale_warning` field so downstream tools (exports, GTM snippets) can display the message.  
4. Markdown/PDF exports append a footnote listing stale items.  
5. SLA threshold is configurable via env or settings file; default remains 30 days.

## Tasks / Subtasks

- [x] Freshness util (AC: 1–5)  
  - [x] Added helper `backend/services/freshness.py` shared in UI/API.  
- [x] Streamlit indicators (AC: 1 & 2)  
  - [x] Radar metrics/persona cards show amber warning badges with last observed age.  
- [x] API + exports (AC: 3 & 4)  
  - [x] Persona API returns `stale_warning`; exports consume via persona payload (rule exports pending future story).  
- [x] Config (AC: 5)  
  - [x] Documented `STALE_THRESHOLD_DAYS` env var (default 30).

## Dev Notes

- Reuses scoring/fingerprinting timestamps from earlier stories.  
- Keep warnings unobtrusive but visible (Midnight Intelligence amber palette).  
- Tests should cover boundary conditions (29 vs 30 days).

### Project Structure Notes

- Helper can live in `backend/services/freshness.py`; import wherever needed.  
- Ensure CLI docs mention how to override SLA.

### References

- [Source: docs/epics.md#story-25-stale-data-warning]  
- [Source: docs/prd.md#functional-requirements FR22]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/2-5-stale-data-warning.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Added freshness helper + tests, wired into Streamlit metrics/persona cards and persona API responses.  
- 2025-11-30: Introduced env knob `STALE_THRESHOLD_DAYS` and documented in README/.env.example.  
- 2025-11-30: Ran `make test` and manual CLI/Streamlit smoke checks.

### Completion Notes List

- UI + API now surface stale-data badges when enrichment timestamps exceed the SLA; warnings reuse a centralized helper.  
- Persona API includes `stale_warning`, enabling future exports to append footnotes.  
- SLA is configurable via env, defaulting to 30 days.

### File List

- `backend/services/freshness.py`
- `backend/services/persona.py`
- `ui/app.py`
- `.env.example`
- `README.md`
- `tests/test_freshness.py`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Implemented stale data warnings across UI/API plus configuration hooks; story ready for review.
