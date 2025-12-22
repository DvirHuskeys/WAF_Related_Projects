# Story 6.2: Role-Based Access Enforcement

Status: ready-for-dev

## Story

As security leads,  
we want basic role-based access controls across the UI and exports,  
so only authorized users can touch sensitive intel, admin settings, or annotations.

## Acceptance Criteria

1. Admin-only sections (Adapter panel, job logs) are hidden unless `ROLE=admin`; unauthorized users see “restricted” messaging.  
2. Persona API, exports, annotations, and copy buttons require roles `admin`, `security`, or `gtm`. `viewer` role can only read the Radar table.  
3. Buttons that a user cannot access are disabled with tooltips explaining why; keyboard focus respects disabled state.  
4. Access denials are logged to `activity_log` with timestamp, role, action, and target.  
5. Role mappings live in `config/roles.yaml` (or `.env`), documented in README, and easily extendable.

## Tasks / Subtasks

- [ ] Role config helper (AC: 5)  
  - [ ] Create `config/roles.yaml` and loader returning permissions per role.  
- [ ] Streamlit enforcement (AC: 1–3)  
  - [ ] Add `require_role("admin")` decorator/helper to gate pages.  
  - [ ] Disable persona/export/annotation buttons for insufficient roles with tooltip.  
- [ ] API enforcement (AC: 2 & 4)  
  - [ ] Persona/export endpoints verify role before executing; log denials.  
- [ ] Logging (AC: 4)  
  - [ ] Extend `activity_log` to include access_denied entries.  
- [ ] Docs (AC: 5)  
  - [ ] README instructions for setting `ROLE` env and editing role map.

## Dev Notes

- Covers PRD FR16 + FR17.  
- Still simple env-based auth but keeps demos safe; later we can plug in real identity provider.  
- Consider default role `admin` for local dev but encourage setting `ROLE=viewer` for read-only sessions.

### Project Structure Notes

- Put helpers in `backend/services/auth.py`; import from UI and API modules.  
- Ensure `config/roles.yaml` is gitignored, with sample file committed.

### References

- [Source: docs/epics.md#story-62-role-based-access-enforcement]  
- [Source: docs/prd.md#functional-requirements FR16]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/6-2-role-based-access.context.xml


### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

