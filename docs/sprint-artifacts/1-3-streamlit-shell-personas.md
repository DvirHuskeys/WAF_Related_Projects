# Story 1.3: Streamlit Shell with Persona Hooks

Status: drafted

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

- [ ] Implement Streamlit layout per UX spec (AC: 1–3)  
  - [ ] Add empty-state container with CLI instructions + button to open docs.  
  - [ ] Render persona selector + placeholder cards pulling dummy narrative text.  
  - [ ] Add metrics cards + table component wired to DuckDB query (fallback to empty dataframe).  
- [ ] Integrate services (AC: 2 & 4)  
  - [ ] Import `backend/services/persona` and `storage` modules; handle missing DB gracefully.  
  - [ ] Log connection errors and show instruction panel.  
- [ ] Apply theme + accessibility (AC: 3)  
  - [ ] Use Midnight Intelligence colors (`docs/ux-color-themes.html`) for buttons/badges.  
  - [ ] Ensure text contrast meets WCAG AA and components have focus outlines.

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

<!-- story-context XML placeholder -->

### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

