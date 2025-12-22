# Story 3.1: Persona API Endpoint

Status: review

## Story

As a GTM consumer,  
I want a `/persona/{id}/{domain}` endpoint (and callable function) that returns stack snapshot, scores, freshness warning, and persona metadata,  
so any tool (Streamlit, exports, CLI) can fetch persona-ready narratives consistently.

## Acceptance Criteria

1. Given DuckDB contains a domain record, when I call `/persona/{persona_id}/{domain}` (or the Python function) then the JSON response includes: domain, detected_waf, detected_cdn, drift/downtime/attack scores, freshness warning, persona metadata (name, goal, focus), story prompt, last_updated.  
2. If the domain is missing, the endpoint returns HTTP 404 with JSON error (“domain not found”) without crashing the app.  
3. Persona IDs are case-insensitive and validated against the configuration; invalid IDs return 400 with helpful message.  
4. API response includes a copyable `story_prompt` string and a structured `hooks` array so UI/export can format nicely.  
5. Function doubles as an internal service (Streamlit imports and Python callers use the same logic).

## Tasks / Subtasks

- [x] Service module (AC: 1,5)  
  - [x] `backend/services/persona.py` returns full payload (story_prompt, hooks, stale_warning) with custom exceptions.  
- [x] FastAPI router (AC: 1–4)  
  - [x] `/persona/{persona_id}/{domain}` returns structured JSON, 400 for invalid persona, 404 for missing domain.  
- [x] Freshness integration (AC: 1 & 4)  
  - [x] Persona responses include freshness warning using shared helper.  
- [x] Tests / docs (AC: 2–5)  
  - [x] Added `tests/test_persona_api.py` plus README section describing usage.

## Dev Notes

- Works with FR5 + FR19; keep persona definitions data-driven (`PERSONA_TEMPLATES`).  
- Ensure persona service only reads from DuckDB (no network).  
- Provide `list_personas()` helper for Story 3.4 UI.

### Project Structure Notes

- Routes can live in `backend/services/persona_api.py` or inside `persona.py`; whichever keeps imports simple for Streamlit.  
- Keep code importable by Streamlit (avoid starting a standalone FastAPI server).

### References

- [Source: docs/epics.md#story-31-persona-api-endpoint]  
- [Source: docs/prd.md#functional-requirements FR5, FR19]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/3-1-persona-api-endpoint.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Expanded persona service with hooks/stale warnings and raised persona/domain-specific errors.  
- 2025-11-30: Updated FastAPI routes + README + tests to cover success/invalid/missing cases.  
- 2025-11-30: `make test` (15 passed).

### Completion Notes List

- Persona API now provides structured persona metadata, scores, hooks, stale warnings, and standard HTTP errors.  
- Streamlit + exports share the same helper, ensuring consistent narratives.  
- Documentation explains how to call the endpoint or Python helper directly.

### File List

- `backend/services/persona.py`
- `backend/services/scoring.py`
- `backend/services/freshness.py`
- `backend/services/hooks.py`
- `config/persona_hooks.yaml`
- `backend/main.py`
- `tests/test_persona_api.py`
- `README.md`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Delivered persona API endpoint and shared helper with freshness/hook support; story ready for review.
