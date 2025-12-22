# Story 6.5: Stale Rule Alerting in Admin

Status: ready-for-dev

## Story

As administrators,  
we want a consolidated view of stale domains/rules with quick actions to re-run enrichment or rule sync,  
so we can keep the sandbox fresh without hunting manually.

## Acceptance Criteria

1. Admin tab displays a table listing domains/rules whose freshness exceeds the SLA, showing type (domain/rule), identifier, last updated, and recommended command.  
2. Each row includes “Copy command” buttons that output the exact CLI command (e.g., `python scripts/domain_enrich.py data/samples/domains.csv --limit 10`) tailored to that item.  
3. Table refreshes when data changes or when the user clicks “Refresh list.”  
4. Warnings integrate with job logging so the table can show whether a re-run recently happened.  
5. README documents how to use the stale alert panel.

## Tasks / Subtasks

- [ ] Data query (AC: 1 & 3)  
  - [ ] Reuse freshness helper to fetch stale domains/rules along with last job ID.  
- [ ] Admin UI (AC: 1–2,4)  
  - [ ] Render table under Admin tab; include copy buttons for CLI hints.  
  - [ ] Show last job status (from `job_runs`).  
- [ ] Documentation (AC: 5)  
  - [ ] README update describing stale alert workflow.

## Dev Notes

- Built on top of Stories 2.5 and 4.4; primarily a UX/reporting layer.  
- Keep copy buttons role-restricted (admin only).

### Project Structure Notes

- Share components with adapter panel (same Admin tab).  
- Queries can live in `backend/services/freshness.py`.

### References

- [Source: docs/epics.md#story-65-stale-rule-alerting-in-admin]  
- [Source: docs/prd.md#functional-requirements FR22]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/6-5-stale-rule-alerting-admin.context.xml


### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

