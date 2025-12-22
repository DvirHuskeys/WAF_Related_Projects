# Story 4.4: Rule Freshness Metadata

Status: review

## Story

As platform teams,  
I want each managed rule annotated with source and sync timestamp,  
so I can see at a glance when to re-run rule sync or question a vendor’s coverage.

## Acceptance Criteria

1. `managed_rules` rows store `source` (e.g., “Cloudflare export”) and `synced_at` timestamp; rule sync CLI populates these fields.  
2. Rule Explorer table (Story 4.1) displays a freshness badge (“Synced 2025‑11‑30”) that turns amber when stale per SLA.  
3. Rule Comparison Drawer (Story 4.2) surfaces freshness metadata in the summary sentence (“AWS rule synced 45d ago”).  
4. Persona/report exports include source + synced_at for any rules referenced.  
5. SLA threshold is configurable (reuse Story 2.5) and warnings share the same helper to avoid duplication.

## Tasks / Subtasks

- [x] Schema update (AC: 1)  
  - [x] `backend/services/storage.py` now provisions `source` + `synced_at` on `managed_rules` (with migrations) and rule sync/seed flows populate those columns.  
- [x] UI updates (AC: 2–3)  
  - [x] Rule Explorer shows “Synced <date>” badges that flip to ⚠️ when past `STALE_THRESHOLD_DAYS`, plus a source column.  
  - [x] Drawer summary + detail cards surface sync/source metadata using the shared freshness helper.  
- [x] Export updates (AC: 4)  
  - [x] Rule exports join aggregated notes and now output `source` + `synced_at` for every rule.  
- [x] Config (AC: 5)  
  - [x] All freshness messaging runs through `backend.services.freshness` (Story 2.5), so SLA thresholds stay consistent.

## Dev Notes

- Stale logic is shared with data warnings; keep util DRY.  
- Consider storing vendor version numbers if available in metadata.

### Project Structure Notes

- Update `backend/services/storage.py` schema definitions.  
- UI changes live alongside existing components.

### References

- [Source: docs/epics.md#story-44-rule-freshness-metadata]  
- [Source: docs/prd.md#functional-requirements FR10, FR22]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/4-4-rule-freshness-metadata.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-12-01: Added schema/adapter updates, UI badges, drawer sync copy, export joins; `make test` (25 passed).

### Completion Notes List

- Managed rules now persist source + synced_at metadata end-to-end (schema, sync CLI, seeding) with migrations for existing DBs.  
- Rule Studio + drawer reuse the shared freshness helper to show badges and summary sentences (“⚠️ synced 42d ago (cloudflare_export)” ).  
- Rule exports append `source`, `synced_at`, and notes so persona/report workflows retain provenance.  
- README documents the badges + env toggles so teams know how to refresh stale vendor data.

### File List

- `backend/services/storage.py`
- `backend/services/export.py`
- `scripts/rule_sync/run.py`
- `scripts/rule_sync/cloudflare.py`
- `scripts/seed_sample_data.py`
- `ui/app.py`
- `ui/components/rule_drawer.py`
- `ui/components/rule_utils.py`
- `tests/test_schema.py`
- `tests/test_rule_utils.py`
- `tests/test_rule_sync.py`
- `tests/test_export.py`
- `README.md`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-12-01: Delivered rule freshness metadata across schema, CLI, UI, and exports; story ready for review.

