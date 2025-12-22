# WAF Security – Architecture Specification

## 1. Project Context & Goals
- **Deployment Reality:** Local-first sandbox meant to run entirely on a lone laptop (Streamlit UI, FastAPI services, DuckDB file storage). No cloud infra, no Postgres/React rewrite—lightweight scripts + HTML artifacts are sufficient so iteration stays fast.
- **Primary Outcomes:**
  1. Fingerprint domains (CLI + FastAPI) and persist results in DuckDB.
  2. Normalize vendor-managed rules for Rule Transparency Studio.
  3. Expose persona APIs + Streamlit UI for GTM Radar and reporting.
  4. Keep everything portable/offline-safe; data never leaves the machine.

## 2. Architecture Overview
```
[Streamlit UI]
    |
    | (in-process imports)
    v
[Persona Service (FastAPI modules)]
    |
    +--> [DuckDB Warehouse]
    |
    +--> [Rule Library adapters]
    |
    +--> [Reporting / Markdown exporters]

[CLI Scripts]
    |
    +--> [domain_enrich.py] --> DuckDB
    +--> [rule_sync/run.py]  --> DuckDB
```
- Everything runs in a single Python process (or simple CLI) with shared virtualenv.
- DuckDB lives under `data/warehouse.db`; raw artifacts (JSON, CSV) under `data/samples/` and `data/rules/`.
- Reporting uses Markdown/HTML files dropped into `docs/` for easy inspection.

## 3. Key Decisions
| Decision | Choice | Rationale |
| --- | --- | --- |
| Runtime | Python 3.9+ Streamlit app invoking FastAPI service modules directly | Avoids multiple services; simplest local dev story. |
| DB | DuckDB file (`data/warehouse.db`) | Zero setup, supports SQL + Parquet exports. |
| Data Ingestion | CLI scripts (`domain_enrich.py`, `rule_sync/run.py`) with Typer | Keep batch jobs explicit, easy to run from terminal. |
| Persona API | FastAPI router imported inside Streamlit session | Simplest way to expose `/persona/...` without separate server. |
| Reporting | Markdown + HTML templates written to `docs/` | Humans can read/share instantly; matches PRD/UX outputs. |
| Filesystem Layout | `backend/services/`, `scripts/`, `data/`, `docs/` | Already adopted; keeps mental model simple. |

## 4. Module Responsibilities
1. **Streamlit UI (`ui/app.py`)**
   - Presents domain list, persona selector, story prompts, raw JSON.
   - Calls persona service functions; displays metrics + call-to-action buttons.
2. **Persona Service (`backend/services/persona.py`, `scoring.py`, `storage.py`)**
   - Fetches enrichment records from DuckDB, derives scores, builds narratives.
   - Provides `generate_persona_view()` and `list_personas()`.
3. **Fingerprinting (`backend/services/fingerprint.py`)**
   - Uses wafw00f heuristics (optional) or random fallback; can be toggled via env `USE_WAFW00F`.
4. **Domain Enrichment CLI (`scripts/domain_enrich.py`)**
   - Reads CSV of domains, populates DuckDB with stack + heuristic scores.
5. **Rule Sync CLI (`scripts/rule_sync/run.py`, adapters)** 
   - Loads vendor rule exports (Cloudflare sample now, others later) into DuckDB `managed_rules`.
6. **Reporting / Docs**
   - Markdown files (brainstorm, research, product brief, PRD, UX) + HTML assets accessible under `docs/`.
   - Future: persona reports + executive briefs (Markdown) appended here.

## 5. Data Model Snapshot (DuckDB)
- `domain_enrichment`
  - `domain TEXT PRIMARY KEY`
  - `detected_waf TEXT`
  - `detected_cdn TEXT`
  - `config_drift_score DOUBLE`
  - `downtime_risk_score DOUBLE`
  - `attack_surface_score DOUBLE`
  - `last_observed TIMESTAMP`
  - `raw JSON`
- `managed_rules`
  - `vendor TEXT`
  - `rule_id TEXT`
  - `name TEXT`
  - `category TEXT`
  - `detection_pattern TEXT`
  - `mitigation TEXT`
  - `severity TEXT`
  - `metadata JSON`

## 6. Operational Notes
- **Environment:** `python3 -m venv .venv` or system Python; install `requirements.txt`.
- **Running the stack:**
  1. `python scripts/domain_enrich.py data/samples/domains.csv`
  2. `python scripts/rule_sync/run.py cloudflare --source data/rules/cloudflare_sample.json`
  3. `streamlit run ui/app.py`
- **Local-only Guarantee:** All data stays inside project folder; no network calls other than optional wafw00f lookups (disabled by default).
- **Backups:** DuckDB file is small; copy `data/warehouse.db` or export to Parquet via DuckDB CLI if needed.

## 7. Future Extensions (when leaving local sandbox)
1. Swap Streamlit for Next.js UI hitting real FastAPI server.
2. Replace DuckDB with managed Postgres; use SQLAlchemy migrations.
3. Containerize via Docker Compose for reproducible dev envs.
4. Add background jobs (Celery/RQ) for enrichment + rule sync scheduling.

For now, we deliberately stay lightweight: one repo, one env, minimal moving parts—all optimized for experimentation on a single laptop.
# Architecture Overview

The local lab is intentionally modular so each experiment can evolve independently while sharing the same DuckDB warehouse.

## Core modules

| Module | Description | Key files |
| --- | --- | --- |
| **Intel Harvester** | Reads domain lists, fingerprints WAF/CDN stacks, and stores scored dossiers. | `scripts/domain_enrich.py`, `backend/services/fingerprint.py` |
| **Managed Rule Library** | Normalizes vendor rule packs into a shared schema for WAFtotal comparisons. | `scripts/rule_sync/*`, DuckDB `managed_rules` table |
| **Scoring Engine** | Derives config-drift/downtime/attack-surface indices and persona-ready narratives. | `backend/services/scoring.py`, `backend/services/persona.py` |
| **Experience Layer** | FastAPI APIs and Streamlit UI that expose GTM Radar and WAFtotal Explorer views. | `backend/main.py`, `ui/app.py` |

## Data Flow

```
domains.csv ──► domain_enrich.py ──► DuckDB.domain_enrichment ─┬─► FastAPI persona endpoints
                                                            │
rules JSON ───► rule_sync/run.py ──► DuckDB.managed_rules ───┘
```

The persona service joins enrichment data with derived scores to produce story prompts. Streamlit calls directly into the service layer for simplicity; switching to HTTP is as simple as pointing the UI at the FastAPI endpoints.

## Running locally

1. Populate DuckDB via `domain_enrich.py` and `rule_sync/run.py`.
2. Start the API: `uvicorn backend.main:app --reload`.
3. Launch the UI: `streamlit run ui/app.py`.

Because everything sits in-process, you can iteratively experiment without provisioning any cloud resources. When ready for hardening, swap DuckDB with Postgres, replace heuristic detectors with real signals, and deploy Streamlit/FastAPI behind your preferred reverse proxy.

