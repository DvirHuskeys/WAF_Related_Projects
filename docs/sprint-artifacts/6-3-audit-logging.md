# Story 6.3: Audit Logging

Status: ready-for-dev

## Story

As compliance-minded users,  
I want every enrichment run, rule sync, persona copy, annotation, or export logged,  
so we can review who did what and detect potential misuse.

## Acceptance Criteria

1. Introduce an `activity_log` DuckDB table with columns: `id`, `timestamp`, `role`, `user_identifier` (optional), `action` (enum), `target` (domain/rule/feature), `details` (JSON).  
2. Every key action (enrichment CLI, rule sync CLI, persona copy, snippet copy, annotation add/edit/delete, adapter changes, board brief export) calls `log_activity(...)`.  
3. Failure events (RBAC denials, CLI errors) are also logged with status `failed`.  
4. CLI or Streamlit admin page can export/view logs (CSV/Parquet) with filters.  
5. README documents how logging works and where data lives.

## Tasks / Subtasks

- [ ] Table + helper (AC: 1)  
  - [ ] Update init script to create `activity_log`.  
  - [ ] Add `backend/services/logging.log_activity`.  
- [ ] Wire actions (AC: 2–3)  
  - [ ] Update CLIs and UI components to call logger.  
  - [ ] Include helpful `details` payloads (counts, rule IDs, etc.).  
- [ ] Viewing/export (AC: 4)  
  - [ ] Admin tab or CLI command to filter/export logs.  
- [ ] Documentation (AC: 5)  
  - [ ] README section for audit logging.

## Dev Notes

- Aligns with FR17; keeps system auditable even in local-first mode.  
- Consider adding `session_id` for long-running tasks later.

### Project Structure Notes

- Logging helper shared with Story 3.3 (persona usage) to avoid duplication.

### References

- [Source: docs/epics.md#story-63-audit-logging]  
- [Source: docs/prd.md#functional-requirements FR17]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/6-3-audit-logging.context.xml


### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

