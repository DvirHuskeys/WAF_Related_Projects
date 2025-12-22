# Story 4.3: Rule Annotation Notes

Status: review

## Story

As security teams,  
I want to attach annotations to managed rules (e.g., “Customer X overrides threshold”),  
so institutional knowledge stays in context when comparing vendor rules.

## Acceptance Criteria

1. From the Rule Explorer or Drawer (Story 4.2), selecting a rule and clicking “Add Note” opens a text input supporting Markdown; saving persists to DuckDB `rule_notes` table with columns `note_id`, `rule_id`, `author`, `timestamp`, `content`.  
2. Existing notes display in the drawer under a “Notes” tab with author + timestamp; notes are sorted newest-first.  
3. Notes can be edited/deleted by the same author (or admin). Actions are logged to `activity_log` (Epic 6).  
4. Persona/report exports include relevant notes for the rules referenced in the story.  
5. Empty-state messaging explains that annotations help track customer-specific tweaks.

## Tasks / Subtasks

- [x] Notes table + helper (AC: 1–3)  
  - [x] Added `rule_notes` + `activity_log` tables via `storage._ensure_tables`, along with `backend/services/rules.py` helper for add/edit/delete + author/role enforcement and `backend/services/activity.py` logger.  
- [x] UI integration (AC: 1–3)  
  - [x] Drawer Notes tab renders per-rule forms (Markdown textarea) + list view with edit/delete controls gated by author/ROLE; actions rerun the Streamlit state for instant feedback.  
- [x] Export integration (AC: 4)  
  - [x] Rule exports join aggregated annotations (`notes` column) so CSV/Parquet deliver context with every rule.  
- [x] Messaging (AC: 5)  
  - [x] Drawer copy explains why annotations matter, shows default author attribution, and adds empty-state guidance.

## Dev Notes

- Align with FR24 (annotations).  
- Consider storing `author` from env/role selection (since no auth system yet).  
- Keep deletion soft (set `deleted_at`) for audit trail.

### Project Structure Notes

- Helpers likely belong in `backend/services/rules.py`.  
- UI forms should appear inside Drawer’s “Notes” section.

### References

- [Source: docs/epics.md#story-43-rule-annotation-notes]  
- [Source: docs/prd.md#functional-requirements FR24]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/4-3-rule-annotation-notes.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-12-01: Added DuckDB schema updates, rule note helpers, activity logger, and regression tests (storage/rules/export).  
- 2025-12-01: Implemented Streamlit drawer Notes tab with forms + RBAC messaging; `make test` (22 passed).

### Completion Notes List

- Notes persist in DuckDB with author + timestamps, plus audit entries in `activity_log` for add/edit/delete (denials logged too).  
- Rule Studio drawer now exposes full annotation UX: Add Note expander, Markdown preview, edit/delete w/ keyboard accessible buttons, and empty-state coaching.  
- Rule exports include a `notes` column summarizing annotations so persona briefs and CSV drops remain contextual.  
- README documents Compare + Notes workflow along with `ANNOTATION_AUTHOR` and `ROLE` env controls.

### File List

- `backend/services/storage.py`
- `backend/services/activity.py`
- `backend/services/rules.py`
- `backend/services/export.py`
- `ui/components/rule_drawer.py`
- `tests/test_schema.py`
- `tests/test_rules.py`
- `tests/test_export.py`
- `README.md`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-12-01: Delivered rule annotations (schema, helpers, UI, exports, docs); story ready for review.
