# Story 6.1: Adapter Configuration Panel

Status: ready-for-dev

## Story

As administrators,  
we want an “Adapter Configuration” page that lists all vendor adapters with toggles and credential fields,  
so we can control which vendors run in the sandbox and manage secrets without editing code.

## Acceptance Criteria

1. Streamlit Admin tab shows a table/list of available adapters (`cloudflare`, `aws_waf`, etc.) with toggle (enabled/disabled), credential input (text/password), and status indicator (last sync).  
2. Changes persist to `config/adapters.yaml` (or `.env`) and are respected by the enrichment/rule-sync CLIs—disabled adapters are skipped unless `--vendor` explicitly overrides.  
3. Secrets are masked in UI; toggling “Show” reveals them temporarily.  
4. Access to Admin tab is restricted by a role flag/env (basic RBAC per Story 6.2). Unauthorized users see “Access denied.”  
5. README documents how to add new adapters and manage the config file.

## Tasks / Subtasks

- [ ] Config loader (AC: 1–2)  
  - [ ] Create `config/adapters.yaml` structure (adapter id, enabled bool, credentials).  
  - [ ] Provide helper to read/write config atomically.  
- [ ] Streamlit admin UI (AC: 1,3,4)  
  - [ ] Add new page/section with adapter cards.  
  - [ ] Mask secrets and enforce role env (e.g., `ROLE=admin`).  
- [ ] CLI integration (AC: 2)  
  - [ ] Rule sync CLI reads config; disabled adapters skipped with info log.  
- [ ] Docs (AC: 5)  
  - [ ] README instructions for editing adapters, storing credentials, overriding via `--vendor`.

## Dev Notes

- Ties to PRD FR15; keep config format simple for local-first environment.  
- Consider storing secrets in `.env` (with `dotenv`) while structural settings remain in YAML.

### Project Structure Notes

- Helpers in `backend/services/config.py`; UI in `ui/admin.py`.  
- Ensure config file is gitignored but sample file (`adapters.example.yaml`) exists.

### References

- [Source: docs/epics.md#story-61-adapter-configuration-panel]  
- [Source: docs/prd.md#functional-requirements FR15]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/6-1-adapter-configuration-panel.context.xml


### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

