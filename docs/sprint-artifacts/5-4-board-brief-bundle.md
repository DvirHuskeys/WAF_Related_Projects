# Story 5.4: Board Brief Bundle

Status: ready-for-dev

## Story

As leadership,  
I want a “Board Brief” button/command that compiles top domains, risks, and differentiation bullets into one packet,  
so I can share an executive-friendly update without manual copy/paste.

## Acceptance Criteria

1. Clicking “Generate Board Brief” creates a Markdown/PDF file `docs/reports/board-brief-<timestamp>.md` containing: summary section, top 5 domains by drift/downtime, key persona hooks per domain, rule transparency highlights (including freshness), and recommended CTAs.  
2. Brief explicitly quotes data sources (timestamps, rule IDs) and includes a log reference (job ID).  
3. UI preview is available; success toast references file path.  
4. CLI command `python scripts/export_board_brief.py` (or a flag in existing export CLI) produces the same output.  
5. README describes usage and how to customize number of domains or data sections.

## Tasks / Subtasks

- [ ] Template + data aggregation (AC: 1–2)  
  - [ ] Build helper that ranks domains by drift/downtime, fetches persona hooks + rule notes, and renders Markdown.  
- [ ] UI/CLI integration (AC: 1,3,4)  
  - [ ] Add button in Streamlit + CLI path for automation.  
  - [ ] Provide preview + toast.  
- [ ] Documentation (AC: 5)  
  - [ ] README instructions for board brief generation and customization.

## Dev Notes

- Reuses components from Stories 5.1–5.3; focus on aggregated narrative.  
- Consider parameterizing domain count or risk threshold via env/config.

### Project Structure Notes

- Template under `docs/templates/board_brief.md.j2`; render via export helper.

### References

- [Source: docs/epics.md#story-54-board-brief-bundle]  
- [Source: docs/prd.md#functional-requirements FR25]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/5-4-board-brief-bundle.context.xml


### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

