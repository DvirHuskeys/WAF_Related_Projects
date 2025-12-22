# WAF Security Local Lab

A local-first sandbox for exploring two complementary ideas:

- **WAFtotal** – reverse engineer managed rules, normalize them, and present vendor-agnostic comparisons that marketing and GTM teams can use instantly.
- **GTM Radar** – enrich domain lists to detect existing WAF/CDN stacks, infer likely pain points (config drift, downtime risk, attack mix), and auto-generate story prompts for sales.

This repository intentionally favors scrappy velocity over production hardening. Everything can run offline on a single laptop via simple Python scripts and Streamlit/FastAPI apps.

## Bootstrap Workflow

1. `make bootstrap` – creates `.venv/` and installs `requirements.txt`.
2. `make env` – copies `.env.example` so you can toggle `USE_WAFW00F`, ports, and DuckDB paths.
3. `make init-db` – runs `scripts/init_duckdb.py` to create `data/warehouse.db` with required tables.
4. `make seed-sample-data` – optional helper to load demo domains and rules for instant UI smoke tests.
5. `make domain-enrich` – runs `python scripts/domain_enrich.py data/samples/domains.csv` (swap the CSV to ingest your list).
6. `source .venv/bin/activate` – activate the environment for manual commands.
7. `make run-ui` – launches Streamlit with the Midnight Intelligence theme from `.streamlit/config.toml`.
8. `make api` – optional FastAPI process for future stories.

### Troubleshooting

- **Pip cannot build wafw00f** – ensure `xcode-select --install` succeeded on macOS, then rerun `make bootstrap`.
- **Port already in use** – set `STREAMLIT_SERVER_PORT=8510 make run-ui` (or update `.env`).
- **DuckDB lock errors** – delete `data/warehouse.db` (sample content regenerates via CLIs) or point `DATA_WAREHOUSE_PATH` to a new file.
- **Missing `.env` overrides** – rerun `make env`; it is idempotent and will not clobber existing values.

## Getting Started

Manual bootstrap remains the same if you prefer raw commands:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/init_duckdb.py
python scripts/seed_sample_data.py
python scripts/domain_enrich.py data/samples/domains.csv
python scripts/rule_sync/run.py --vendor cloudflare --source data/rules/cloudflare_sample.json
uvicorn backend.main:app --reload
streamlit run ui/app.py
```

## Domain Ingestion CLI

- `python scripts/domain_enrich.py your_domains.csv [--limit N] [--dry-run]`
- CSV must include a `domain` column; invalid or duplicate domains are skipped with warnings.
- `--dry-run` previews enrichment without writing to DuckDB.
- Shortcut: `make domain-enrich` runs the CLI against `data/samples/domains.csv`.
- Set `STALE_THRESHOLD_DAYS` in `.env` (default 30) to control when stale badges appear in the UI/API.

## Rule Sync CLI

- `python scripts/rule_sync/run.py vendor --source path/to/export.json`
- Vendor adapters live in `scripts/rule_sync/` (see `docs/adapters.md` for the interface).
- CLI prints inserted/updated counts and can be invoked via `make rule-sync` for the Cloudflare sample.

## Export Utilities

- `python scripts/export_data.py --domains --format csv` (or `--rules/--usage`, `--format parquet`)
- Output files land under `exports/` (override via `EXPORT_DIR` env var). Job IDs are recorded in `job_runs` for auditing.
- Streamlit offers quick buttons for generating domains/rules/usage CSV or Parquet files; use them after seeding data.
- Shortcuts: `make export-domains`, `make export-rules`, and `make export-usage`.

## Radar Summary Export

- Generate one-pagers via CLI: `python scripts/export_radar_summary.py example.com --persona ae --pdf --show`.
- Markdown files land in `docs/reports/<domain>-radar-<timestamp>.md` (override with `--output-dir`). Add `--pdf` to create a lightweight PDF twin.
- The Streamlit persona column now includes a **Generate Radar Summary** button that previews the Markdown and shows the saved paths plus a toast.
- Templates live under `docs/templates/radar_summary.md.jinja`; update the Jinja file to adjust sections or copy tone.

## Rule Transparency Brief Export

- Compare two vendor rules via CLI: `python scripts/export_rule_brief.py acme.com cloudflare:1000 aws_waf:2000 --pdf --show`.
- Briefs save to `docs/reports/<domain>-rule-brief-<timestamp>.md` (plus optional `.pdf`). Each brief includes comparison tables, mitigation notes, annotations, and references the latest rule-sync job.
- Inside Streamlit, open Rule Studio, select two rules, and use the **Rule Brief Export** drawer controls to enter a domain, toggle PDF output, preview the Markdown, and copy the saved paths from the toast.
- Templates live under `docs/templates/rule_brief.md.jinja`; adjust sections or recommended messaging from there.

Refer to `docs/architecture.md` for the module breakdown and `docs/playbook/story-prompts.md` for persona-driven story hooks.

## Testing

```bash
python -m pytest
```

## Persona API

- FastAPI endpoint: `GET /persona/{persona_id}/{domain}` returns stack snapshot, scores, freshness warning, hooks, and story prompt.
- Invalid personas respond with HTTP 400; missing domains return HTTP 404.
- See `backend/main.py` (run via `make api`) or import `backend.services.persona.generate_persona_view()` directly in Python.

## Persona Usage Logging

- Usage events are written to the `persona_usage` table whenever the Streamlit “Copy Story Prompt” button is clicked or when the API is called (unless `?log_usage=false`/`include_usage=false`).
- Disable logging by setting `DISABLE_PERSONA_LOGGING=1` in `.env` (default is enabled).
- View the latest events: `duckdb data/warehouse.db "SELECT * FROM persona_usage ORDER BY created_at DESC LIMIT 20;"`.
- Reset the log if needed: `duckdb data/warehouse.db "DELETE FROM persona_usage;"`.
- Export usage data via CLI (`python scripts/export_data.py --usage --format csv`), Streamlit buttons, or `make export-usage`.

## Rule Studio

- Scroll down in the Streamlit app to open Rule Studio—a filterable grid for `managed_rules` showing vendor, category, severity, freshness, and last synced time.
- Filter by vendor/category/severity/freshness, search by name/ID, and multi-select rows for future comparisons.
- If the grid is empty, run `python scripts/rule_sync/run.py cloudflare --source data/rules/cloudflare_sample.json` (or `make rule-sync`) to seed sample data.
- Click **Compare selected** (requires two selections) to open the comparison drawer with diff summary, detail cards, and annotations.
- Use the **Notes** tab inside the drawer to capture Markdown comments per rule. Set `ANNOTATION_AUTHOR` (default: OS user) and `ROLE` (`admin` grants edit rights across all notes) in `.env` to control attribution and permissions.
- Notes persist to DuckDB (`rule_notes`) and their add/edit/delete events are logged to `activity_log`. Rule exports now include a `notes` column summarizing the annotations for each rule.
- Freshness badges (“✅ Synced 2025-11-30”) are powered by `synced_at` metadata and flip to ⚠️ when they exceed `STALE_THRESHOLD_DAYS`, reminding you to rerun `rule_sync`.

See `docs/testing.md` for the manual smoke checklist.

