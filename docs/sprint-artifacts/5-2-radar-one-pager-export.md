# Story 5.2: GTM Radar One-Pager Export

Status: review

## Story

As AE Alex,  
I want to click “Generate Radar Summary” for a domain and receive a Markdown/PDF one-pager,  
so I can share stack snapshot, scores, hooks, and next steps with my team or prospects.

## Acceptance Criteria

1. Given a domain is selected, when I click “Export Radar Summary” then a Markdown file is saved to `docs/reports/<domain>-radar-<timestamp>.md` containing sections: Stack Snapshot, Risk Signals (drift/downtime/attack), Persona Hooks, Recommended Next Steps, Freshness note.  
2. Optionally convert Markdown to PDF using `markdown-pdf` or `fpdf` (flag/checkbox).  
3. Export references the job ID and persona `story_prompt`, includes citations for data sources (timestamps, rule metadata).  
4. UI shows preview before download; success toast indicates file location.  
5. README documents how to run export via CLI or Streamlit.

## Tasks / Subtasks

- [x] Template + renderer (AC: 1–3)  
  - [x] Create Jinja template for radar summary; include placeholders per acceptance criteria.  
  - [x] Implement export helper that writes Markdown and optionally PDF.  
- [x] UI integration (AC: 1–4)  
  - [x] Add “Generate Radar Summary” button to dashboard or persona cards.  
  - [x] Show preview (e.g., `st.markdown` with template output).  
  - [x] Provide download link + toast.  
- [x] CLI entry point (optional) (AC: 5)  
  - [x] Add `scripts/export_radar_summary.py` for automation.  
- [x] Docs (AC: 5)  
  - [x] Update README/Makefile with usage instructions.

## Dev Notes

- Reuse persona service + scoring to populate fields.  
- Ensure styling matches Midnight Intelligence (e.g., use inline badges).  
- When converting to PDF, keep dependencies lightweight (fpdf or markdown-pdf).

### Project Structure Notes

- Templates under `docs/templates/` or `backend/templates/`.  
- Export helper resides in `backend/services/export.py` with other exporters.

### References

- [Source: docs/epics.md#story-52-gtm-radar-one-pager-export]  
- [Source: docs/prd.md#functional-requirements FR12, FR14]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/5-2-radar-one-pager-export.context.xml


### Agent Model Used

_TBD during implementation_

### Debug Log References

- 2025-12-02 – Plan for Template + renderer / UI / CLI scope:
  1. Build `docs/templates/radar_summary.md.jinja` capturing Stack Snapshot, Risk Signals, Persona Hooks, Recommended Steps, Freshness, Citations (AC1–AC3).
  2. Extend `backend/services/export.py` with a radar summary helper that pulls domain + persona data, stamps job_id, writes Markdown + optional PDF (AC1–AC3).
  3. Add UI button + preview/toast in `ui/app.py` plus session state cache so users can trigger export and see file path (AC4).
  4. Provide Typer CLI in `scripts/export_radar_summary.py` and README instructions so exports run headless (AC5).
  5. Update story artifacts (tasks, file list, change log) once validation/tests succeed.
- 2025-12-02 – Implemented radar exports end-to-end:
  - Authored `docs/templates/radar_summary.md.jinja` with stack snapshot, risk signals, hooks, next steps, and citation sections; swapped non-ASCII characters for PDF-safe output.
  - Extended `backend/services/export.py` with `generate_radar_summary` (Markdown+optional PDF), template rendering helpers, ASCII normalization, and tests for Markdown/PDF flows.
  - Added Streamlit controls in `ui/app.py` (checkbox + button + preview + toast) tied to session state to satisfy AC4.
  - Delivered Typer CLI `scripts/export_radar_summary.py`, README instructions, and regression coverage in `tests/test_export.py`.
  - Updated freshness warnings to ASCII, expanded requirements (Jinja2/fpdf), and ran `python3 -m pytest` (28 passed).

### Completion Notes List

- 2025-12-02 – AC1–AC5 met: Markdown + optional PDF exports stored under `docs/reports`, UI preview + toast wired, CLI available for automation, README documents workflow, and regression tests cover export and freshness flows.

### File List

- docs/templates/radar_summary.md.jinja
- backend/services/export.py
- backend/services/freshness.py
- ui/app.py
- scripts/export_radar_summary.py
- README.md
- requirements.txt
- tests/test_export.py
- tests/test_freshness.py
- docs/sprint-artifacts/5-2-radar-one-pager-export.md
