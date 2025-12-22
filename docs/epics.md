# WAF Security - Epic Breakdown

**Author:** Compa  
**Date:** 2025-11-30  
**Project Level:** Level 1 (Discovery → Planning)  
**Target Scale:** Internal local-first sandbox

---

## Overview

This document decomposes the WAF Security PRD into user-value epics and single-session stories so Phase 4 implementation agents can work autonomously. Each epic results in a tangible capability that GTM, security, or platform users can exercise, while Epic 1 provides the minimal foundation required for any functionality to exist.

Epics:
1. Foundation Sandbox & Data Layer
2. Domain Intelligence Pipeline
3. Persona Intelligence Service
4. Rule Transparency Studio
5. GTM Radar & Reporting Experience
6. Administration, Governance & Extensibility

---

## Functional Requirements Inventory

- **FR1:** Operations staff can upload CSV domain lists (or call the CLI) to trigger enrichment jobs that fingerprint WAF/CDN stacks without contacting production systems.  
- **FR2:** The system stores enrichment outputs (detected WAF/CDN, drift/downtime/attack-surface scores, raw artifacts) in DuckDB with provenance timestamps.  
- **FR3:** Rule Sync adapters can ingest managed-rule exports per vendor (starting with Cloudflare) and normalize them into the shared schema with freshness metadata.  
- **FR4:** Enrichment and rule sync jobs expose completion/status events so other modules (persona service, reporting) can react without polling.  
- **FR5:** Persona API exposes `/persona/{id}/{domain}` responses containing stack snapshot, scores, and curated story prompts for AE Alex, CISO Cassandra, and Platform Winston.  
- **FR6:** Persona logic must map score thresholds to recommended “pitch angles” that GTM teams can quote verbatim.  
- **FR7:** The system tracks persona usage metadata (domain, persona id, timestamp) for KPI reporting.  
- **FR8:** Users can browse normalized managed rules by vendor, attack category, severity, and freshness.  
- **FR9:** The UI/API can compare at least two vendor rules side by side.  
- **FR10:** The system annotates each rule with freshness/origin metadata.  
- **FR11:** Streamlit UI lists enriched domains, sortable by drift/downtime/attack score, and links directly to persona cards.  
- **FR12:** Users can generate GTM Radar one-pagers summarizing stack snapshot, scores, hooks, and next steps.  
- **FR13:** Executives can export Rule Transparency briefs (Markdown/PDF).  
- **FR14:** Generated reports include citation references to enrichment timestamps and rule sources.  
- **FR15:** Admins can configure active vendor adapters, API keys, and sync cadence.  
- **FR16:** Role-based access controls restrict sensitive intel to authorized personas.  
- **FR17:** The system logs all enrichment, rule sync, report generation, and persona API calls.  
- **FR18:** Users can download enriched data and rule libraries as CSV/Parquet.  
- **FR19:** Persona API must support additional personas without redeployment.  
- **FR20:** Vendor adapters implement a shared interface for future additions.  
- **FR21:** CLI commands accept configuration flags (limit, vendor, source path).  
- **FR22:** The system flags stale data (e.g., rule exports older than 30 days) and surfaces warnings.  
- **FR23:** GTM users can copy/paste persona story prompts and GTM Radar cards into CRM/email tools with formatting preserved.  
- **FR24:** Security teams can annotate rule comparisons with internal notes.  
- **FR25:** Executives can request a “board brief” bundle combining top domains, risks, and differentiators.

---

## FR Coverage Map

| Epic | FRs Covered |
| --- | --- |
| 1. Foundation Sandbox & Data Layer | Supports all FRs by providing repo/env, DuckDB schema, and Streamlit skeleton (no direct FR assignment) |
| 2. Domain Intelligence Pipeline | FR1, FR2, FR3, FR4, FR18, FR21, FR22 |
| 3. Persona Intelligence Service | FR5, FR6, FR7, FR19, FR23 |
| 4. Rule Transparency Studio | FR3, FR8, FR9, FR10, FR24 |
| 5. GTM Radar & Reporting Experience | FR11, FR12, FR13, FR14, FR18, FR23, FR25 |
| 6. Administration, Governance & Extensibility | FR15, FR16, FR17, FR20, FR22 |

All FRs have at least one epic home; overlaps (e.g., FR3, FR18, FR23, FR22) are intentional where capabilities span modules.

---

## Epic 1: Foundation Sandbox & Data Layer

Establishes the local-first environment, repository scaffolding, DuckDB schema, and Streamlit shell so subsequent epics can deliver value.

### Story 1.1: Initialize Local Sandbox
As an internal developer, I want a reproducible repo + virtualenv scaffold so that contributors can run Streamlit/FastAPI/DuckDB locally without extra setup.  
**Acceptance Criteria**  
• **Given** the repo is cloned fresh  
• **When** I run `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`  
• **Then** dependencies install without manual edits  
• **And** `.streamlit`, `data/`, `docs/`, `backend/`, `scripts/`, `ui/` folders exist with starter files  
**Prerequisites** None  
**Technical Notes** Include `.env.example`, document `USE_WAFW00F` toggle, add `Makefile` or README commands.

### Story 1.2: Establish DuckDB Schema
As a developer, I want a repeatable script that creates the DuckDB database and required tables so enrichment jobs have a place to persist records.  
**Acceptance Criteria**  
• **Given** I run `python scripts/init_duckdb.py`  
• **When** `data/warehouse.db` does not exist  
• **Then** tables `domain_enrichment` and `managed_rules` are created with PRD columns  
• **And** re-running the script is idempotent  
**Prerequisites** Story 1.1  
**Technical Notes** Use migrations within `backend/services/storage.py`; ensure JSON support is enabled.

### Story 1.3: Streamlit Shell with Persona Hooks
As a GTM user, I want to open a Streamlit page that renders domain tables and persona dropdowns even before data exists, so I can see the workflow skeleton.  
**Acceptance Criteria**  
• **Given** I run `streamlit run ui/app.py` on a clean DB  
• **When** no domains exist  
• **Then** the UI shows an empty-state warning referencing enrichment CLI  
• **And** persona dropdown pulls from `persona_service.list_personas()`  
**Prerequisites** Stories 1.1–1.2  
**Technical Notes** Apply Midnight Intelligence theme tokens; include placeholder metrics cards.

### Story 1.4: Sample Data Loader
As a developer, I want a script that seeds demo domains and Cloudflare rules so demos work immediately.  
**Acceptance Criteria**  
• **Given** sample CSV and JSON files exist  
• **When** I run `python scripts/seed_sample_data.py`  
• **Then** DuckDB contains at least four domain rows and two rule rows identical to the samples  
• **And** Streamlit UI refreshes automatically showing those rows  
**Prerequisites** Story 1.2  
**Technical Notes** Reuse enrichment and rule sync CLIs; log each step.

---

## Epic 2: Domain Intelligence Pipeline

Deliver ingest, fingerprinting, storage, status, and freshness capabilities that power GTM Radar.

### Story 2.1: CSV Ingestion CLI
As an operations teammate, I want to run `python scripts/domain_enrich.py mylist.csv` so that domain fingerprints populate without editing code.  
**Acceptance Criteria**  
• **Given** a CSV with a `domain` header  
• **When** I run the command with optional `--limit` flag  
• **Then** the CLI validates the file, prints progress per domain, and writes rows into `domain_enrichment`  
• **And** invalid rows are skipped with warnings, not crashes  
**Prerequisites** Epic 1 stories  
**Technical Notes** Use Typer; exit non-zero on fatal errors; provide `--dry-run`.

### Story 2.2: Fingerprinting & Scoring Pipeline
As an enrichment job, I want to detect WAF/CDN providers and heuristic scores so persona service has consistent inputs.  
**Acceptance Criteria**  
• **Given** a domain fetched from the CLI  
• **When** fingerprinting runs  
• **Then** `detected_waf`, `detected_cdn`, drift/downtime/attack scores, `last_observed`, and raw JSON are stored  
• **And** `USE_WAFW00F` env flag toggles real wafw00f usage vs random fallback  
**Prerequisites** Story 2.1  
**Technical Notes** Wrap wafw00f calls with timeouts; seed random values for offline mode.

### Story 2.3: Rule Sync Adapter Framework
As a platform engineer, I want to add vendor adapters via `scripts/rule_sync/` so new rule packs can be normalized without touching persona code.  
**Acceptance Criteria**  
• **Given** I run `python scripts/rule_sync/run.py cloudflare --source data/rules/cloudflare_sample.json`  
• **When** the adapter finishes  
• **Then** `managed_rules` rows are inserted with vendor, rule_id, metadata, and timestamps  
• **And** creating `aws_waf.py` only requires implementing `load_rules()` returning the standard dict schema  
**Prerequisites** Story 2.1  
**Technical Notes** Validate metadata JSON, enforce severity/category defaults.

### Story 2.4: Enrichment Status & CLI Flags
As an operator, I want CLI output and stored status rows so I know whether enrichment/sync succeeded.  
**Acceptance Criteria**  
• **Given** I run either CLI  
• **When** processing begins  
• **Then** the CLI prints a progress bar and writes start/end timestamps plus status to a `job_runs` DuckDB table  
• **And** both CLIs honor `--limit`, `--vendor`, `--source` flags per FR21  
**Prerequisites** Stories 2.1–2.3  
**Technical Notes** Minimal job tracking table with job_id, type, started_at, finished_at, status, error.

### Story 2.5: Stale Data Warning
As a persona or GTM user, I want to see freshness alerts when enrichment or rule sync data is older than 30 days so I can re-run jobs.  
**Acceptance Criteria**  
• **Given** any domain or rule record older than the threshold  
• **When** Streamlit UI renders or persona API responds  
• **Then** a warning badge appears (“Data is 37 days old – re-run enrichment”) and exports include the same warning  
**Prerequisites** Story 2.4  
**Technical Notes** Compare timestamps vs `datetime.utcnow()`; surface warnings via badges + Markdown footers.

### Story 2.6: Data Export Utilities
As an analyst, I want to export enriched data and rule libraries as CSV/Parquet so I can slice them in notebooks.  
**Acceptance Criteria**  
• **Given** I click “Download domains CSV” or call a CLI flag  
• **When** DuckDB has data  
• **Then** a file saves under `exports/` with ISO timestamp in filename and column headers per schema  
**Prerequisites** Stories 2.1–2.3  
**Technical Notes** Use DuckDB `COPY`; expose Streamlit download buttons.

---

## Epic 3: Persona Intelligence Service

Expose persona-aware insights, scoring explanations, and copy-ready prompts that GTM and security teams trust.

### Story 3.1: Persona API Endpoint
As a GTM consumer, I want `/persona/{id}/{domain}` to return stack snapshot, scores, freshness, and persona metadata so I can embed it anywhere.  
**Acceptance Criteria**  
• **Given** DuckDB contains a domain row  
• **When** I call the endpoint (or persona function)  
• **Then** JSON includes domain, detected WAF/CDN, drift/downtime/attack scores, freshness warning, persona label, and story prompt  
**Prerequisites** Epic 2  
**Technical Notes** Use FastAPI response models; handle 404 when domain missing.

### Story 3.2: Score-to-Story Mapping
As AE Alex, I want story hooks tailored to score ranges so I can open with the most relevant pain.  
**Acceptance Criteria**  
• **Given** scoring config defines thresholds  
• **When** a domain crosses high drift or downtime thresholds  
• **Then** persona prompt includes the recommended hook text (“Lead with configuration coherence”) with copy-ready formatting  
**Prerequisites** Story 3.1  
**Technical Notes** Keep mappings in config file for easy tweaks; align language with UX copy guidelines.

### Story 3.3: Persona Usage Logging
As RevOps, I want to know which personas and domains are being copied so I can measure adoption.  
**Acceptance Criteria**  
• **Given** persona UI or API response is shown  
• **When** the user clicks “Copy story” or `include_usage=true` query param  
• **Then** a `persona_usage` table row records domain, persona id, timestamp, and channel (UI/API)  
**Prerequisites** Story 3.1  
**Technical Notes** Provide toggle to disable logging for privacy; include CLI to export usage stats.

### Story 3.4: Persona Card UI with Copy Button
As GTM users, we want persona cards inside Streamlit that match the UX spec so storytelling is frictionless.  
**Acceptance Criteria**  
• **Given** persona data exists  
• **When** I select a domain + persona  
• **Then** the card shows persona avatar, stack snapshot, hook text, copy button with “Copied!” state, and shortcuts to exports  
**Prerequisites** Stories 3.1–3.3, Story 1.3  
**Technical Notes** Implement using Streamlit columns + custom CSS; respect accessibility focus states.

---

## Epic 4: Rule Transparency Studio

Enable security and platform teams to inspect, compare, and annotate managed rules across vendors.

### Story 4.1: Rule Explorer Grid
As a security analyst, I want a tabular view of managed rules filterable by vendor, category, severity, and freshness so I can scan coverage quickly.  
**Acceptance Criteria**  
• **Given** managed_rules table has rows  
• **When** I open “Rule Studio” tab  
• **Then** the grid displays vendor, rule id, name, category, severity, freshness badge, and includes filter chips + search  
**Prerequisites** Epic 2 Story 2.3  
**Technical Notes** Use Streamlit AgGrid or built-in table; highlight stale rules with amber border per UX spec.

### Story 4.2: Rule Comparison Drawer
As CISO Cassandra, I want to select two rules (e.g., Cloudflare vs AWS) and view differences side-by-side so I can explain gaps.  
**Acceptance Criteria**  
• **Given** I select two rows  
• **When** I click “Compare”  
• **Then** a right-hand drawer opens showing detection pattern, mitigation, severity, metadata, freshness, and summary sentence of differences  
**Prerequisites** Story 4.1  
**Technical Notes** Drawer component from UX spec; include copy-to-clipboard for diff summary.

### Story 4.3: Rule Annotation Notes
As security teams, we want to attach annotations to rules (e.g., “Customer X overrides threshold”) so institutional knowledge stays in context.  
**Acceptance Criteria**  
• **Given** I view a rule  
• **When** I add a note and click Save  
• **Then** the note persists to DuckDB `rule_notes` with author + timestamp and displays for anyone viewing that rule  
**Prerequisites** Story 4.1  
**Technical Notes** Provide Markdown support; log edits in audit trail (Epic 6).

### Story 4.4: Rule Freshness Metadata
As platform teams, we want each rule annotated with source + sync timestamp so we know when to refresh.  
**Acceptance Criteria**  
• **Given** rule metadata contains `synced_at` and `source`  
• **When** the UI renders  
• **Then** each rule card shows “From Cloudflare export • synced 2025‑11‑30” and stale ones show warning icon  
**Prerequisites** Story 2.5  
**Technical Notes** Use same stale-threshold util as Epic 2 Story 2.5; include in persona/report exports.

---

## Epic 5: GTM Radar & Reporting Experience

Deliver the user-visible Radar table, persona-linked actions, and export workflows that GTM and exec teams rely on.

### Story 5.1: Radar Dashboard Table
As GTM teams, we want a sortable domain table showing drift/downtime/attack scores with quick persona chips so we can prioritize outreach.  
**Acceptance Criteria**  
• **Given** enrichment data exists  
• **When** I view the dashboard  
• **Then** each row shows domain, WAF/CDN icons, scores with color-coded badges, freshness indicator, and a “View personas” button that opens Story 3.4 cards  
**Prerequisites** Epics 1–3  
**Technical Notes** Implement sticky header, column sorting, saved filters in URL params.

### Story 5.2: GTM Radar One-Pager Export
As AE Alex, I want to click “Generate Radar Summary” for a domain so I get a Markdown/PDF with stack snapshot, scores, hook, and recommended next step.  
**Acceptance Criteria**  
• **Given** I select a domain  
• **When** I click export  
• **Then** a Markdown file saves to `docs/reports/` with sections (Stack Snapshot, Risk Signals, Persona Hooks, Next Steps) and renders in Streamlit preview  
**Prerequisites** Story 5.1, Story 3.2  
**Technical Notes** Use Jinja template; include citations referencing `last_observed`.

### Story 5.3: Rule Transparency Brief Export
As executives, we want a brief comparing vendor rules for a domain so we can justify renewal or migrations.  
**Acceptance Criteria**  
• **Given** at least two vendor rules exist  
• **When** I run “Export Rule Brief”  
• **Then** Markdown includes comparison table, key differences, freshness warnings, and recommended messaging, satisfying FR13–FR14  
**Prerequisites** Epic 4 stories  
**Technical Notes** Reuse diff summary from Story 4.2; include optional attachments (charts) later.

### Story 5.4: Board Brief Bundle
As leadership, I want a single command or button that compiles top domains, biggest risks, and differentiation bullets into a ready-to-share packet.  
**Acceptance Criteria**  
• **Given** I click “Generate Board Brief”  
• **When** at least one domain is enriched  
• **Then** Markdown/PDF includes top 5 domains by drift, key persona hooks, rule deltas, and CTA for each; file name includes date and `board-brief` slug  
**Prerequisites** Stories 5.1–5.3  
**Technical Notes** Derived from FR25; reuse sections from prior exports but grouped.

### Story 5.5: Copy-Friendly Persona + Radar Snippets
As GTM reps, I want “Copy message” buttons on both persona cards and radar rows so I can paste into CRM/email without reformatting.  
**Acceptance Criteria**  
• **Given** I hover a persona or radar row  
• **When** I click “Copy message”  
• **Then** clipboard contains a Markdown/Plaintext snippet with bolded hook and inline citation, and toast confirms copy  
**Prerequisites** Stories 3.4 & 5.1  
**Technical Notes** Maps to FR23; preserve markdown characters, include CRM-friendly variant.

---

## Epic 6: Administration, Governance & Extensibility

Provide adapter toggles, RBAC, logging, and extension hooks so the sandbox stays safe and future-proof.

### Story 6.1: Adapter Configuration Panel
As administrators, we want a Streamlit admin page that lists all vendor adapters with toggle + credential fields so we can control what runs.  
**Acceptance Criteria**  
• **Given** I open “Admin” tab  
• **When** I flip a toggle or edit API key  
• **Then** settings persist to `config/adapters.yaml`, CLIs respect them, and UI badges show active adapters  
**Prerequisites** Story 1.3, Story 2.3  
**Technical Notes** Protect page via env flag; mask secrets in UI, store in `.env`.

### Story 6.2: Role-Based Access Enforcement
As security leads, we want RBAC so only authorized users can view sensitive targets or run reports.  
**Acceptance Criteria**  
• **Given** `roles.yaml` defines Admin/Security/GTM/Viewer  
• **When** the app loads  
• **Then** unauthorized roles cannot see admin tab, annotations, or sensitive exports; persona/report endpoints validate role before returning data  
**Prerequisites** Story 6.1  
**Technical Notes** For Streamlit, use simple login select or environment variable to simulate roles; log unauthorized attempts.

### Story 6.3: Audit Logging
As compliance-minded users, I want every enrichment run, rule sync, persona copy, annotation, or export logged so we can review later.  
**Acceptance Criteria**  
• **Given** any of those actions occur  
• **When** they complete  
• **Then** an `activity_log` DuckDB table row captures timestamp, actor, action, metadata, and result  
**Prerequisites** Relevant stories from other epics  
**Technical Notes** Provide CLI to export logs; ensure logs referenced in FR17.

### Story 6.4: Adapter Interface Contract
As future developers, we want a documented adapter protocol so new vendors can be added quickly.  
**Acceptance Criteria**  
• **Given** I read `docs/adapters.md`  
• **When** I implement a new adapter  
• **Then** the doc clearly states required functions, fields, validation, and how to register it in CLI + UI  
**Prerequisites** Story 2.3  
**Technical Notes** Covers FR20; include code snippet template.

### Story 6.5: Stale Rule Alerting in Admin
As admins, we want a consolidated view of stale data across domains/rules so we can schedule re-runs.  
**Acceptance Criteria**  
• **Given** some records exceed freshness SLA  
• **When** I open Admin tab  
• **Then** a table lists them with buttons to trigger enrichment/sync CLIs (prints command to console)  
**Prerequisites** Story 2.5  
**Technical Notes** Reuses stale util; provide copyable shell commands.

---

## FR Coverage Matrix

| FR | Epic & Story |
| --- | --- |
| FR1 | Epic 2 – Story 2.1 |
| FR2 | Epic 2 – Story 2.2 |
| FR3 | Epic 2 – Story 2.3; Epic 4 – Stories 4.1–4.4 |
| FR4 | Epic 2 – Story 2.4 |
| FR5 | Epic 3 – Story 3.1 |
| FR6 | Epic 3 – Story 3.2 |
| FR7 | Epic 3 – Story 3.3 |
| FR8 | Epic 4 – Story 4.1 |
| FR9 | Epic 4 – Story 4.2 |
| FR10 | Epic 4 – Story 4.4 |
| FR11 | Epic 5 – Story 5.1 |
| FR12 | Epic 5 – Story 5.2 |
| FR13 | Epic 5 – Story 5.3 |
| FR14 | Epic 5 – Story 5.3 |
| FR15 | Epic 6 – Story 6.1 |
| FR16 | Epic 6 – Story 6.2 |
| FR17 | Epic 6 – Story 6.3 |
| FR18 | Epic 2 – Story 2.6; Epic 5 – Story 5.2 |
| FR19 | Epic 3 – Story 3.1/3.2 |
| FR20 | Epic 6 – Story 6.4 |
| FR21 | Epic 2 – Story 2.4 |
| FR22 | Epic 2 – Story 2.5; Epic 6 – Story 6.5 |
| FR23 | Epic 3 – Story 3.4; Epic 5 – Story 5.5 |
| FR24 | Epic 4 – Story 4.3 |
| FR25 | Epic 5 – Story 5.4 |

---

## Summary

The epic breakdown now covers all 25 FRs with vertically sliced stories grounded in UX and architecture context:

- **Foundation** ensures Streamlit/FastAPI/DuckDB sandbox runs locally.  
- **Domain Intelligence** builds ingestion, scoring, rule sync, and freshness guardrails.  
- **Persona Intelligence** turns scores into copy-ready prompts with telemetry.  
- **Rule Transparency** enables analysts to inspect, compare, and annotate managed rules.  
- **GTM Radar & Reporting** provides the domain dashboard and export workflows GTM + execs rely on.  
- **Administration & Governance** handles adapter toggles, RBAC, auditing, and extensibility.

All stories reference specific acceptance criteria and implementation notes so development agents can immediately begin `create-story` for prioritized items.

---

_For implementation: use the `create-story` workflow to convert each story into execution-ready specs. This document will evolve if UX or Architecture add new context._


