# Story 5.1: Radar Dashboard Table

Status: review

## Story

As GTM teams,  
I want a sortable domain table (GTM Radar) showing drift/downtime/attack scores with persona hooks,  
so I can prioritize outreach and jump straight into the right story.

## Acceptance Criteria

1. Radar table lists domains with columns: Domain, Detected WAF/CDN (icons), Drift/Downtime/Attack scores (color-coded badges), Freshness warning, Persona quick links (buttons).  
2. Table supports sorting by any score and filtering by vendor, persona relevance, or freshness status; filters persist via `st.session_state`.  
3. Selecting a row (or clicking persona button) scrolls to / opens the persona cards (Story 3.4).  
4. Layout matches UX spec (Midnight Intelligence theme, responsive two-column layout) and supports empty-state messaging.  
5. Data auto-refreshes when enrichment job completes (poll job log or provide “Refresh” button).

## Tasks / Subtasks

- [x] Table rendering (AC: 1–4)  
  - [x] Query `domain_enrichment` and format into pandas/AgGrid table with color badges.  
  - [x] Add vendor icons (emoji or small PNG).  
  - [x] Provide persona buttons per row.  
- [x] Filtering/persistence (AC: 2)  
  - [x] Add multi-select filters + search bar; store selections in session state.  
- [x] Row selection integration (AC: 3)  
  - [x] Clicking persona button triggers `st.session_state["selected_domain"]` and jumps to persona section.  
- [x] Refresh hooks (AC: 5)  
  - [x] Add “Refresh data” button or auto-refresh interval after job success.  
- [x] Theme polish (AC: 4)  
  - [x] Apply consistent spacing, focus outlines, accessibility tags.

## Dev Notes

- Reuse scoring + freshness helpers.  
- Consider caching to avoid repeated DuckDB calls; use `st.cache_data`.

### Project Structure Notes

- Table logic can live in `ui/components/radar_table.py`.  
- Keep `ui/app.py` orchestrating the page sections.

### References

- [Source: docs/epics.md#story-51-radar-dashboard-table]  
- [Source: docs/ux-design-specification.md#key-interactions]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/5-1-radar-dashboard-table.context.xml


### Agent Model Used

_TBD during implementation_

### Debug Log References

- 2025-12-02: Introduced `ui/components/radar_table.py` with persistent filters, persona quick links, and job-aware refresh hooks tied to Streamlit state.
- 2025-12-02: Restructured `ui/app.py` into dual-column radar/persona layout with CSS badges that follow the Midnight Intelligence theme.

### Completion Notes List

- ✅ Radar table now renders WAF/CDN icons, sortable score badges, persona buttons, and scroll-linked cards while metrics/exports live beside the grid.
- ✅ Added DuckDB job introspection + regression tests so enrichment completions trigger automatic UI refreshes without manual polling.

### File List

- ui/components/radar_table.py
- ui/app.py
- backend/services/jobs.py
- tests/test_jobs.py

### Change Log

- 2025-12-02: Delivered Story 5.1 radar dashboard experience plus job-status plumbing to satisfy AC1–AC5.

