# Story 5.5: Copy-Friendly Persona & Radar Snippets

Status: ready-for-dev

## Story

As GTM reps,  
I want “Copy message” buttons on persona cards and radar rows that produce CRM/email-ready text,  
so I can drop insights into outreach without reformatting.

## Acceptance Criteria

1. Persona cards (Story 3.4) include a button that copies a Markdown/Plaintext snippet: bolded hook, stack snapshot, freshness note, citation (e.g., “Source: Radar export 2025‑11‑30”).  
2. Radar table rows include a “Copy snippet” button next to each domain, producing a shorter summary focused on scores + recommended opening line.  
3. Snippets respect persona-specific language (AE vs CISO) and include optional CRM tags (e.g., `[Deal Name]`).  
4. Copy actions trigger success toast and log to `persona_usage` (Story 3.3) with action “copy_snippet”.  
5. README documents how the snippets are structured and how to tweak templates.

## Tasks / Subtasks

- [ ] Snippet template (AC: 1–3 & 5)  
  - [ ] Create template(s) for persona vs radar snippets (maybe Jinja in `backend/templates/snippets`).  
  - [ ] Support plain text and markdown versions.  
- [ ] Persona integration (AC: 1,4)  
  - [ ] Persona card copy button uses template + logs usage.  
- [ ] Radar integration (AC: 2,4)  
  - [ ] Add copy button per row; includes CTA referencing persona hook.  
- [ ] Documentation (AC: 5)  
  - [ ] README section describing snippet customization.

## Dev Notes

- Aligns with PRD FR23.  
- Keep snippet templates short and on-brand; include placeholders for CRM tokens if needed.

### Project Structure Notes

- Templates live under `backend/templates/` or similar; reuse via helper function from persona/radar modules.

### References

- [Source: docs/epics.md#story-55-copy-friendly-persona--radar-snippets]  
- [Source: docs/prd.md#functional-requirements FR23]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/5-5-copy-friendly-snippets.context.xml


### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

