# Story 1.1: Initialize Local Sandbox

Status: drafted

## Story

As an internal developer,  
I want a reproducible repository and virtualenv scaffold,  
so that everyone can run the Streamlit/FastAPI/DuckDB stack locally without extra setup.

## Acceptance Criteria

1. Given the repo is freshly cloned, when I run `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`, then dependencies install without manual edits.  
2. The codebase contains baseline folders `.streamlit/`, `data/`, `docs/`, `backend/`, `scripts/`, and `ui/` (with placeholder files or README stubs) after bootstrap.  
3. A `.env.example` documents toggles such as `USE_WAFW00F`, and the root README (or Makefile) lists the bootstrap commands.

## Tasks / Subtasks

- [ ] Bootstrap virtualenv workflow (AC: 1)  
  - [ ] Add bootstrap section to `README.md` (commands + troubleshooting).  
  - [ ] Commit `.env.example` with documented vars (`USE_WAFW00F`, `STREAMLIT_SERVER_PORT`, etc.).  
- [ ] Scaffold project directories (AC: 2)  
  - [ ] Ensure `.streamlit/config.toml`, `data/.gitkeep`, `docs/.gitkeep`, `backend/__init__.py`, `scripts/__init__.py`, `ui/__init__.py` exist.  
  - [ ] Add placeholder files explaining folder purpose (short README or comments).  
- [ ] Add developer convenience scripts (AC: 3)  
  - [ ] Create a `Makefile` (or `scripts/bootstrap.sh`) invoking the documented commands.  
  - [ ] Verify `streamlit run ui/app.py` prints the empty-state warning (smoke test).

## Dev Notes

- Foundation aligns with the architecture goal of “local-first sandbox” (see `docs/architecture.md#1-project-context--goals`). Avoid adding external dependencies or services.  
- Keep dependency list minimal (FastAPI, DuckDB, Streamlit, Typer, Rich, etc. per `requirements.txt`).  
- Document `.env` toggles so future stories (fingerprinting, persona service) can reuse the same config surface.

### Project Structure Notes

- Root directories now match the UX/Architecture expectations (`backend/services/...`, `ui/app.py`, `scripts/*.py`).  
- Use snake_case for script names (`seed_sample_data.py`) and keep modules importable by Streamlit (i.e., add `__init__.py` in package folders). No conflicts detected.

### References

- [Source: docs/epics.md#story-11-initialize-local-sandbox]  
- [Source: docs/architecture.md#1-project-context--goals]

## Dev Agent Record

### Context Reference

<!-- Path(s) to story context XML will be added here by context workflow -->

### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

