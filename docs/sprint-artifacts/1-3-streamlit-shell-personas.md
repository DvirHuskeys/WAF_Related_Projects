# Story 1.3: Streamlit Shell with Persona Hooks

Status: review

## Story

As a GTM user,  
I want the Streamlit app to render domain tables, persona selectors, and empty-state messaging even before data exists,  
so that I can see the workflow skeleton and understand how GTM Radar will work once data is ingested.

## Acceptance Criteria

1. Given I run `streamlit run ui/app.py` against an empty DuckDB, when the page loads then I see an empty-state panel telling me to run the enrichment CLI with the exact command.  
2. Persona dropdowns populate from `persona_service.list_personas()` regardless of data availability, and selecting a persona shows placeholder cards referencing the UX spec layout.  
3. Metrics cards (drift/downtime/attack) and domain table placeholders render using Midnight Intelligence theme tokens, with skeleton loaders until real data arrives.  
4. The app reuses the shared storage helper to connect to DuckDB; connection errors show a friendly message with troubleshooting hints.

## Tasks / Subtasks

- [x] Implement Streamlit layout per UX spec (AC: 1–3)  
  - [x] Add empty-state container with CLI instructions + button to open docs.  
  - [x] Render persona selector + placeholder cards pulling dummy narrative text.  
  - [x] Add metrics cards + table component wired to DuckDB query (fallback to empty dataframe).  
- [x] Integrate services (AC: 2 & 4)  
  - [x] Import `backend/services/persona` and `storage` modules; handle missing DB gracefully.  
  - [x] Log connection errors and show instruction panel.  
- [x] Apply theme + accessibility (AC: 3)  
  - [x] Use Midnight Intelligence colors (`docs/ux-color-themes.html`) for buttons/badges.  
  - [x] Ensure text contrast meets WCAG AA and components have focus outlines.

## Dev Notes

- Follow UX design spec Sections “Project & Users” and “Core Experience Principles”: the empty state should keep users oriented and highlight the Radar-to-Story handoff.  
- Expect to replace placeholders once Stories 2.1–3.4 deliver real data, so isolate UI components into helper functions for reuse.  
- Keep everything local-first (no external APIs beyond optional wafw00f toggle).  
- Consider adding Streamlit sidebar nav stubs for upcoming epics (Rule Studio, Admin).

### Project Structure Notes

- `ui/app.py` should import reusable helpers from `backend/services`. Keep Streamlit file slim by delegating domain table rendering to `ui/components.py` if necessary.  
- No conflicting files detected; follow snake_case for new component modules.

### References

- [Source: docs/epics.md#story-13-streamlit-shell-with-persona-hooks]  
- [Source: docs/ux-design-specification.md#project--users-project_and_users_confirmed]  
- [Source: docs/ux-color-themes.html]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/1-3-streamlit-shell-personas.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Refactored `ui/app.py` with theme injection, persona placeholders, metrics/table helpers, and connection-safe data loading so AC1–AC4 can be exercised without DuckDB data.
- 2025-11-30: Added empty-state instructions referencing `python scripts/domain_enrich.py ...` plus error guidance (`make init-db`) to satisfy UX + troubleshooting requirements.
- 2025-11-30: Verified regression suite (`make test`) to ensure schema helpers + UI imports remain green.

### Completion Notes List

- Streamlit page now always loads persona selector + cards, renders Midnight Intelligence-themed metrics/table placeholders, and degrades gracefully when no enrichment data exists.
- Added friendly empty state and connection error messaging; both list exact bootstrap commands for users.
- Live data path still renders metrics, tables, persona prompts, and raw record details when DuckDB contains domains.

### File List

- `ui/app.py`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Implemented Streamlit shell placeholders, theme styling, and connection-safe UX; story ready for review.
