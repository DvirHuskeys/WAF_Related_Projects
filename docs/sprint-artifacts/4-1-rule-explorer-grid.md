# Story 4.1: Rule Explorer Grid

Status: review

## Story

As a security analyst,  
I want a tabular “Rule Studio” view that lists normalized managed rules with filters and freshness indicators,  
so I can quickly scan coverage across vendors before diving into comparisons.

## Acceptance Criteria

1. The Rule Studio page displays a table with columns: vendor, rule_id, name, category, severity, freshness badge, and last synced timestamp (from DuckDB).  
2. Users can filter by vendor, category, severity, and freshness (stale vs fresh) via chips or dropdowns; search box matches rule name/id.  
3. Table supports multi-select (checkboxes) for downstream comparisons (Story 4.2); selected count displayed.  
4. Layout uses Midnight Intelligence theme tokens and follows UX density guidelines (cards with subtle borders, sticky header).  
5. Empty state explains how to run rule sync CLI if no rules exist.

## Tasks / Subtasks

- [x] Streamlit table implementation (AC: 1–4)  
  - [x] Query DuckDB via `storage.list_rules()` into pandas; add filters for vendor/category/severity/freshness/search plus sticky layout.  
- [x] Selection hooks (AC: 3)  
  - [x] `st.data_editor` checkbox column with persistent selection count + “Compare selected” CTA (placeholder for Story 4.2).  
- [x] Empty state (AC: 5)  
  - [x] Inline instructions point to `scripts/rule_sync/run.py` when no rules exist.  
- [x] Theme polish (AC: 4)  
  - [x] Badges + warning colors reuse Midnight Intelligence tokens; freshness uses shared helper.

## Dev Notes

- Ensure table pagination or virtualization to handle large sets.  
- Consider caching DuckDB query for improved performance.

### Project Structure Notes

- Add `ui/pages/rule_studio.py` or component helper to keep `app.py` manageable.  
- Reuse stale helper from Story 2.5.

### References

- [Source: docs/epics.md#story-41-rule-explorer-grid]  
- [Source: docs/ux-design-specification.md#core-experience-principles]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/4-1-rule-explorer-grid.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Added `storage.list_rules()` and Rule Studio UI section with filters, stale badges, and selection storage.  
- 2025-11-30: README updated with Rule Studio guidance; `make test` (19 passed).

### Completion Notes List

- Rule Explorer grid now lives inside Streamlit with vendor/category/severity/freshness filters, search box, multi-select, and last-synced timestamps derived from metadata.  
- Empty state links to rule sync CLI; selection state is persisted for future comparison drawer.

### File List

- `backend/services/storage.py`
- `tests/test_schema.py`
- `ui/app.py`
- `README.md`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Implemented Rule Studio grid with filters, freshness badges, and selection scaffolding; story ready for review.
