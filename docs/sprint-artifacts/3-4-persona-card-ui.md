# Story 3.4: Persona Card UI with Copy Button

Status: review

## Story

As GTM users,  
we want persona cards inside Streamlit that mirror the UX spec—including avatars, scores, hooks, and copy-to-clipboard buttons—  
so storytelling becomes frictionless once data is available.

## Acceptance Criteria

1. Persona cards display: persona avatar/icon, name, goal snippet, stack snapshot (WAF/CDN), drift/downtime/attack scores with badges, freshness warning, and main hook text.  
2. “Copy message” button copies the story prompt + citation to clipboard, showing a “Copied!” toast and subtle state change for 2 seconds.  
3. Secondary hooks appear as badges or bullet list items; clicking them updates the main hook preview.  
4. Cards respect Midnight Intelligence theme, spacing, and accessibility requirements (focus outlines, readable colors).  
5. Empty-state: if no persona data exists, the panel explains how to run enrichment CLI; when data exists, cards update instantly.

## Tasks / Subtasks

- [x] Persona card component (AC: 1–4)  
  - [x] Created `ui/components/persona_card.py` with avatars, stack snapshot, score metrics, hook badges, and freshness warnings.  
- [x] Copy button (AC: 2)  
  - [x] Copy-to-clipboard uses a JS snippet + toast + 2-second state change; keyboard activation handled via native Streamlit button.  
- [x] Secondary hooks (AC: 3)  
  - [x] Horizontal radio badges switch the primary hook preview; badges render inline for quick scanning.  
- [x] Empty state + data refresh (AC: 5)  
  - [x] Empty card explains enrichment CLI; added “Refresh Persona Data” button to rerun the query.

## Dev Notes

- Reuse `generate_persona_view()` output from Story 3.1; no duplicate logic.  
- Keep layout responsive (two cards per row on desktop, stacked on mobile).  
- Optionally cache persona data to avoid repeated DB hits.

### Project Structure Notes

- Consider `ui/components/persona_card.py` helper to avoid clutter in `ui/app.py`.  
- Ensure CSS/JS stays minimal since Streamlit doesn’t allow heavy DOM manipulation.

### References

- [Source: docs/epics.md#story-34-persona-card-ui-with-copy-button]  
- [Source: docs/ux-design-specification.md#user-experience-principles]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/3-4-persona-card-ui.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Introduced reusable persona card component with avatars, metrics, hooks, copy button, and badges per UX spec.  
- 2025-11-30: Added Streamlit refresh control + usage logging callback; `make test` (18 passed).

### Completion Notes List

- Persona UI now mirrors the spec: avatars, stack snapshot, score badges, hook selection, freshness warning, and copy interaction.  
- Copy button writes to clipboard, shows toast + temporary state, and logs usage via backend helper.  
- Empty state directs users to enrichment CLI and provides refresh button.

### File List

- `ui/components/persona_card.py`
- `ui/components/__init__.py`
- `ui/app.py`
- `backend/services/logging.py`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Delivered persona card UX with copy + hook interactions; story ready for review.
