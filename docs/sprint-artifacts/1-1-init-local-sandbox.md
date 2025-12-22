# Story 1.1: Initialize Local Sandbox

Status: review

## Story

As an internal developer,  
I want a reproducible repository and virtualenv scaffold,  
so that everyone can run the Streamlit/FastAPI/DuckDB stack locally without extra setup.

## Acceptance Criteria

1. Given the repo is freshly cloned, when I run `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`, then dependencies install without manual edits.  
2. The codebase contains baseline folders `.streamlit/`, `data/`, `docs/`, `backend/`, `scripts/`, and `ui/` (with placeholder files or README stubs) after bootstrap.  
3. A `.env.example` documents toggles such as `USE_WAFW00F`, and the root README (or Makefile) lists the bootstrap commands.

## Tasks / Subtasks

- [x] Bootstrap virtualenv workflow (AC: 1)  
  - [x] Add bootstrap section to `README.md` (commands + troubleshooting).  
  - [x] Commit `.env.example` with documented vars (`USE_WAFW00F`, `STREAMLIT_SERVER_PORT`, etc.).  
- [x] Scaffold project directories (AC: 2)  
  - [x] Ensure `.streamlit/config.toml`, `data/.gitkeep`, `docs/.gitkeep`, `backend/__init__.py`, `scripts/__init__.py`, `ui/__init__.py` exist.  
  - [x] Add placeholder files explaining folder purpose (short README or comments).  
- [x] Add developer convenience scripts (AC: 3)  
  - [x] Create a `Makefile` (or `scripts/bootstrap.sh`) invoking the documented commands.  
  - [x] Verify `streamlit run ui/app.py` prints the empty-state warning (smoke test).

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

- docs/sprint-artifacts/1-1-init-local-sandbox.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Planned bootstrap deliverables (README section, `.env.example`, Makefile, placeholder docs) plus validations (streamlit smoke test + pytest) before touching story metadata.
- 2025-11-30: Bootstrapped `.venv`, installed requirements, and launched headless `streamlit run ui/app.py` on port 9995 to confirm the empty-state warning renders for fresh databases.
- 2025-11-30: Initial `make test` failed (pytest could not import `backend`). Added `tests/conftest.py` to force the repo root onto `sys.path`, re-ran `pytest` + `make test`, and both succeeded.

### Completion Notes List

- Bootstrap instructions now live in `README.md` with troubleshooting guidance and align with the new `Makefile` + `.env.example`.
- Added `.streamlit/config.toml`, directory READMEs, gitkeep placeholders, and package `__init__.py` files so the scaffold survives fresh clones.
- Makefile + tests verified via `make bootstrap`, headless `streamlit run`, and `make test` (after adding the pytest sys.path helper).

### File List

- `.env.example`
- `.gitignore`
- `.streamlit/config.toml`
- `.streamlit/README.md`
- `Makefile`
- `README.md`
- `backend/README.md`
- `scripts/__init__.py`
- `scripts/README.md`
- `ui/__init__.py`
- `ui/README.md`
- `data/.gitkeep`
- `data/README.md`
- `docs/.gitkeep`
- `docs/README.md`
- `tests/conftest.py`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Completed Story 1.1 bootstrap deliverables (env workflow, documentation, scaffolding, smoke tests) and marked the story ready for review.
