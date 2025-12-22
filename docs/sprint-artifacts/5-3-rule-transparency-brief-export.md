# Story 5.3: Rule Transparency Brief Export

Status: review

## Story

As executives,  
I want to export a narrative comparing vendor rules for a domain,  
so I can justify renewals or migrations with evidence from Rule Transparency Studio.

## Acceptance Criteria

1. Given at least two vendor rules exist for the selected domain, when I click “Export Rule Brief” then a Markdown file saves to `docs/reports/<domain>-rule-brief-<timestamp>.md` summarizing: vendor comparison table, detection pattern differences, mitigation notes, freshness metadata, annotations (Story 4.3), and recommended messaging.  
2. Brief includes citations referencing rule sync job ID and note authors.  
3. Option to render PDF similar to Story 5.2.  
4. UI preview is available prior to download; success toast references file path.  
5. README documents how to run via CLI or Streamlit.

## Tasks / Subtasks

- [x] Template + renderer (AC: 1–3)  
  - [x] Create Markdown template pulling from rule comparison data + notes.  
  - [x] Integrate with export helper for PDF option.  
- [x] UI integration (AC: 1–4)  
  - [x] Add “Export Rule Brief” button to Rule Studio / Drawer.  
  - [x] Provide preview + download link.  
- [x] CLI option (AC: 5)  
  - [x] Add optional script (or extend existing export CLI).  
- [x] Documentation (AC: 5)  
  - [x] Update README with instructions.

## Dev Notes

- Reuses output from Stories 4.2 and 4.3; ensure the export handles stale metadata (Story 4.4).  
- Summaries should echo persona hooks for CISO Cassandra.

### Project Structure Notes

- Template under `docs/templates/`; use same export helper as Story 5.2.

### References

- [Source: docs/epics.md#story-53-rule-transparency-brief-export]  
- [Source: docs/prd.md#functional-requirements FR13, FR14]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/5-3-rule-transparency-brief-export.context.xml


### Agent Model Used

_TBD during implementation_

### Debug Log References

- 2025-12-02 – Implementation plan:
  1. Author `docs/templates/rule_brief.md.jinja` capturing comparison table, detection/mitigation diffs, freshness notes, annotations, recommended messaging, and citations referencing rule sync job + note authors (AC1–AC2).
  2. Extend `backend/services/export.py` with `generate_rule_brief` (fetch rules + notes, build summary, Markdown/PDF, CLI hooks) plus new CLI `scripts/export_rule_brief.py` (AC1–AC3 & AC5).
  3. Enhance Streamlit Rule Drawer to accept selected domain, expose "Export Rule Brief" controls with preview + toast, and thread domain selection from the radar section (AC4).
  4. Update README/docs with instructions, wire `requirements.txt` if additional deps needed (reuse existing), and add regression tests for Markdown/PDF generation (AC5).
- 2025-12-02 – Implementation complete:
  - Authored template and backend renderer, shipped CLI + README docs, added Rule Drawer export controls, and expanded pytest coverage (30 passing).

### Completion Notes List

- 2025-12-02 – AC1–AC5 satisfied: Markdown/PDF briefs saved under `docs/reports/<domain>-rule-brief-<timestamp>.md`, cite latest rule-sync job + note authors, include comparison tables + recommended messaging, UI preview/toast flows wired, CLI available, README updated, and `python3 -m pytest` passes (30 tests).

### File List

- docs/templates/rule_brief.md.jinja
- backend/services/export.py
- scripts/export_rule_brief.py
- ui/app.py
- ui/components/rule_drawer.py
- README.md
- tests/test_export.py
- docs/sprint-artifacts/5-3-rule-transparency-brief-export.md

