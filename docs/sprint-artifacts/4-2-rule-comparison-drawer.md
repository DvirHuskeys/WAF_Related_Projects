# Story 4.2: Rule Comparison Drawer

Status: review

## Story

As CISO Cassandra,  
I want to select two vendor rules and view differences side-by-side in a drawer,  
so I can explain gaps and portability issues during renewals or migrations.

## Acceptance Criteria

1. From Rule Explorer (Story 4.1), selecting ≥2 rules and clicking “Compare” opens a right-side drawer showing: vendor names, detection patterns, mitigation descriptions, severity, freshness, and a summary sentence describing the delta.  
2. Drawer supports comparing exactly two rules; selecting more prompts user to pick which two.  
3. Copy-to-clipboard button exports the diff summary (“Cloudflare Rule 100000 blocks SQLi via query parser; AWS rule lacks freshness, last synced 45d ago”).  
4. Drawer includes tabs or sections: “Diff Summary”, “Details”, “Notes” (ties into Story 4.3).  
5. UI respects UX guidelines (Midnight Intelligence theme, accessible focus order) and closes via ESC or [x].

## Tasks / Subtasks

- [x] Drawer component (AC: 1–5)  
  - [x] Added right-column drawer container with Midnight theme embellishments and ESC instructions.  
  - [x] Cards show vendor, ID, mitigation, detection pattern, severity badge, and freshness with stale-age callouts plus color-coded diff chips.  
- [x] Selection logic (AC: 1–2)  
  - [x] Rule Studio now tracks selected rows, enables “Compare selected” only when ≥2 rules, and passes selections into drawer; if more than two are chosen, dropdowns prompt the user to pick the comparison pair.  
- [x] Copy summary (AC: 3)  
  - [x] Diff summary sentence concatenates vendor, pattern, mitigation, severity deltas, and freshness; copy button reuses shared clipboard helper and toasts success.  
- [x] Tabs/sections (AC: 4)  
  - [x] Drawer renders “Diff Summary”, “Details”, and “Notes” tabs (Notes stub references Story 4.3).  
- [x] Accessibility (AC: 5)  
  - [x] Drawer describes ESC/Tab behavior, keeps focusable controls in one column, and ensures copy/button controls are keyboard-activated.

## Dev Notes

- Diff summary should highlight detection/mitigation differences and freshness warnings from Story 2.5.  
- Consider using Python `difflib` for detection pattern diff (optional).  
- Notes tab will connect to Story 4.3 annotations.

### Project Structure Notes

- Drawer logic can live in `ui/components/rule_drawer.py`.  
- Keep state (selected rule IDs, tab) in `st.session_state`.

### References

- [Source: docs/epics.md#story-42-rule-comparison-drawer]  
- [Source: docs/ux-design-specification.md#core-experience-principles]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/4-2-rule-comparison-drawer.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-12-01: Implemented Rule Studio drawer with compare workflow, diff chips, copy helper refactor, and new selection state machine.  
- 2025-12-01: Added `make test` regression run (18 passed).

### Completion Notes List

- Rule Studio now surfaces a structured comparison drawer with diff summary, detail cards, and upcoming Notes tab, matching UX spec.  
- Selection gating + dropdown overrides keep comparisons scoped to exactly two rules and provide guidance when >2 are selected.  
- Drawer diff summary includes mitigation/pattern/freshness gaps, and users can copy the narrative with toast feedback.  
- Accessibility + Midnight styling updates keep focus states, ESC guidance, and diff chips visually consistent.

### File List

- `ui/app.py`
- `ui/components/rule_drawer.py`
- `ui/components/rule_utils.py`
- `ui/components/utils.py`
- `ui/components/persona_card.py`
- `backend/services/storage.py`
- `tests/test_schema.py`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-12-01: Delivered rule comparison drawer with diff summary, detail cards, and copy-to-clipboard workflow; story ready for review.

