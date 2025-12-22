# WAF Security - Product Requirements Document

**Author:** Compa
**Date:** 2025-11-30
**Version:** 1.0

---

## Executive Summary

WAF Security establishes a local-first “insight spine” that combines WAFtotal (vendor-agnostic managed-rule transparency) with GTM Radar (domain fingerprinting + storytelling) so every security, architecture, and GTM conversation starts with evidence instead of guesswork. By harvesting domain signals, normalizing Cloudflare/AWS/Akamai rule packs, and packaging the findings into persona-ready prompts, we enable teams to spot drift, justify renewals, and craft differentiated narratives in minutes.

### What Makes This Special

The differentiator is neutrality plus speed: a single internal lab that can ingest any domain, translate managed rules across vendors, and emit tailored assets (stack snapshots, executive briefs, GTM hooks) without touching production infrastructure or waiting on vendor dashboards.

---

## Project Classification

**Technical Type:** saas_b2b
**Domain:** general (security tooling)
**Complexity:** medium

This is a SaaS-style internal platform with multi-tenant-style personas (AE Alex, CISO Cassandra) and cross-vendor data ingestion. Domain complexity is medium because we’re dealing with enterprise-grade security narratives but not regulated sectors like healthcare or fintech. The product leans on existing research (`docs/research-market-2025-11-30.md`) and the product brief (`docs/product-brief-WAF Security-2025-11-30.md`) as upstream context.

Product Brief Source: `docs/product-brief-WAF Security-2025-11-30.md`  
Research Materials: `docs/research-market-2025-11-30.md`

---

## Success Criteria

1. **Intelligence Adoption:** Enrich at least 100 target domains per week and ensure 60% of active opportunities attach at least one persona story prompt.
2. **Narrative Impact:** GTM teams report a measurable lift in win rate (target 25% influence on closed-won deals) when GTM Radar insights are used.
3. **Rule Transparency Trust:** Maintain managed-rule freshness where 95% of entries are updated within 30 days, with at least three vendor libraries (Cloudflare, AWS, Akamai) synthesized.
4. **Executive Usability:** Deliver board-ready “Rule Transparency” briefs within minutes for renewals and migrations—validated via stakeholder satisfaction surveys/interviews.

---

## Product Scope

### MVP - Minimum Viable Product

- DuckDB warehouse populated via `domain_enrich.py` and `rule_sync/run.py` (Cloudflare to start).
- FastAPI persona service with `/persona/{id}/{domain}` endpoints returning stack snapshot + story prompt.
- Streamlit UI that lists enriched domains and surfaces drift/downtime/attack scores alongside persona cards.
- Reporting template (Markdown/PDF) for executive and GTM handoff.

### Growth Features (Post-MVP)

- Additional vendor adapters (AWS WAF, Akamai, F5, Imperva).
- Automated Rule Remix lab for translating rule logic across stacks.
- Threat rehearsal/animation outputs for marketing campaigns.
- Basic CRM integration to push GTM Radar cards into target accounts.

### Vision (Future)

- Real-time telemetry ingestion (Shodan, Censys, passive DNS) to boost detection confidence.
- Automated executive brief generator with slide export + story suggestions per persona.
- Threat simulation “stage” that animates how rule packs respond to attacks for webinars and analyst briefings.
- Fully vendor-agnostic rule marketplace (“GitHub for managed rules”) with sharing/version control.

---

## SaaS B2B Specific Requirements

SaaS controls ensure GTM, security, and architecture stakeholders can share one platform without cross-contamination of data or messaging.

### Multi-Tenancy Architecture
- Logical partitioning by “workspace” (e.g., internal teams, partner overlays) so each group sees only its domain lists, reports, and annotations.
- Shared DuckDB schema must include tenant/workspace keys to simplify future migration to a multi-tenant Postgres instance.

### Permissions & Roles
- Roles: Admin (configure adapters + secrets), Security (rule explorer, annotations), GTM (persona + reporting), Viewer (read-only).
- RBAC enforced at API and UI layers; persona prompts or executive briefs should not leak domains across roles unless explicitly shared.

### Subscription & Packaging Model
- Internal “packages” mimic customer tiers (Essentials = GTM Radar, Pro = adds Rule Transparency Studio, Enterprise = full automation) to test value narratives before externalizing.
- Feature flags tied to packages to control access without redeploying services.

### Integration Surface
- Enumerate supported integrations per MVP (CSV import/export, CLI, REST). Growth roadmap includes CRM push/pull, Slack/Email notifications.
- Document contract for adapter interface so partners (e.g., MSSPs) can contribute vendor plugins later.

### Compliance & Audit
- Even though internal, logs must capture who accessed which domain intel for audit readiness; store in append-only log table.
- Prepare for future SOC2-style evidence by documenting data flows and retention policies now.

---

## Innovation & Novel Patterns

- **Neutral Rule Remixing:** Treat managed rules as portable building blocks rather than vendor-specific black boxes, enabling “Rule Transparency Studio” experiences uncommon in WAF tooling.
- **Persona-Aware GTM Intel:** Blend domain telemetry with copy-ready prompts so every outreach campaign is data-backed, effectively turning a security dataset into GTM fuel.
- **Local-First Architecture:** Running entirely on local infra (DuckDB + FastAPI + Streamlit) means we can iterate quickly, experiment offline, and still simulate enterprise-grade insights.

### Validation Approach
- Validate rule translation accuracy by cross-checking a subset of rules against vendor documentation and live configs.
- Run pilot GTM campaigns using GTM Radar prompts; gather win/loss feedback to ensure narratives resonate.
- Perform internal security reviews to confirm local-first architecture does not leak sensitive target intel.

---

## User Experience Principles

- **Data-first clarity:** emphasize scores, narratives, and rule metadata before chrome; Streamlit layout should foreground actionable intel (“config drift high → lead with coherence”).
- **One-click storytelling:** persona cards and reports expose “Copy narrative” buttons so GTM users can drop language into CRM/email without editing.
- **Traceable insights:** every view surfaces freshness timestamps and source links, reinforcing trust and making executive brief generation trivial.

### Key Interactions
- Domain list table with filters (drift/downtime/attack) → selecting a domain opens persona cards side-by-side.
- Rule Transparency view with tabs per vendor and a comparison mode for cross-stack storytelling.
- Report builder wizard guiding users through selecting domains, persona, and output format, culminating in Markdown/PDF export.

---

## Functional Requirements
**Intelligence Harvesting**
- **FR1:** Operations staff can upload CSV domain lists (or call the CLI) to trigger enrichment jobs that fingerprint WAF/CDN stacks without contacting production systems.
- **FR2:** The system stores enrichment outputs (detected WAF/CDN, drift/downtime/attack-surface scores, raw artifacts) in DuckDB with provenance timestamps.
- **FR3:** Rule Sync adapters can ingest managed-rule exports per vendor (starting with Cloudflare) and normalize them into the shared schema with freshness metadata.
- **FR4:** Enrichment and rule sync jobs expose completion/status events so other modules (persona service, reporting) can react without polling.

**Persona Intelligence**
- **FR5:** Persona API exposes `/persona/{id}/{domain}` responses containing stack snapshot, scores, and curated story prompts for AE Alex, CISO Cassandra, and Platform Winston.
- **FR6:** Persona logic must map score thresholds to recommended “pitch angles” (e.g., config drift → “lead with configuration coherence”) that GTM teams can quote verbatim.
- **FR7:** The system tracks persona usage metadata (domain, persona id, timestamp) for KPI reporting.

**Rule Transparency Studio**
- **FR8:** Users can browse normalized managed rules by vendor, attack category, severity, and freshness.
- **FR9:** The UI/API can compare at least two vendor rules side by side, highlighting differences in detection pattern, mitigations, and coverage gaps.
- **FR10:** The system annotates each rule with freshness (days since last sync) and origin (vendor export vs. public doc) so CISOs can assess trustworthiness.

**GTM Radar & Reporting**
- **FR11:** Streamlit UI lists enriched domains, sortable by drift/downtime/attack score, and links directly to persona cards.
- **FR12:** Users can generate GTM Radar one-pagers that summarize stack snapshot, scores, hook narrative, and recommended outreach steps.
- **FR13:** Executives can export Rule Transparency briefs (Markdown/PDF) that include vendor comparisons, differentiators, and recommended messaging.
- **FR14:** Generated reports include citation references (linking back to enrichment timestamp and rule sources) for auditability.

**Administration & Governance**
- **FR15:** Admins can configure which vendor adapters are active, set API keys/credentials, and schedule sync cadence.
- **FR16:** Role-based access controls ensure sensitive intel (e.g., target domains, rule exports) is visible only to authorized GTM or security personnel.
- **FR17:** The system logs all enrichment, rule sync, report generation, and persona API calls for compliance review.

**Data Management & Extensibility**
- **FR18:** Users can download enriched data and rule libraries as CSV/Parquet for offline analysis.
- **FR19:** The persona API must support additional personas (e.g., RevOps Riley) without redeploying core services—persona definitions are data-driven.
- **FR20:** Vendor adapters must implement a shared interface so new vendors can be added without modifying the persona/reporting logic.
- **FR21:** CLI commands (`domain_enrich.py`, `rule_sync/run.py`) accept configuration flags (limit, vendor, source path) for experimentation.
- **FR22:** The system flags stale data (e.g., rule exports older than 30 days) and surfaces warnings in the UI and reports.

**Collaboration & Sharing**
- **FR23:** GTM users can copy/paste persona story prompts and GTM Radar cards directly into CRM/email tools with formatting preserved.
- **FR24:** Security teams can annotate rule comparisons with internal notes (e.g., “Customer X overriding rule Y”) that stay attached to that rule view.
- **FR25:** Executives can request a “board brief” bundle combining top domains, key risks, and differentiators for the next meeting.

---

## Non-Functional Requirements

### Performance
- Enrichment runs must handle at least 500 domains per batch without manual throttling, providing progress feedback in CLI/UI.
- Persona API responses should return within 2 seconds for cached/enriched domains; fallback messaging when data is stale.

### Security
- Store only public-domain data (WHOIS, headers) plus derived scores; strip any PII before persistence.
- Role-based access must ensure only authorized teams can view target domain intel; all secrets (API keys) stored via env/secret manager.

### Scalability
- DuckDB warehouse schema must tolerate 100k+ domain records and multi-vendor rule catalogs without performance degradation, with a migration path to Postgres if needed.
- Adapter framework must allow parallel vendor syncs without cross-contamination of metadata.

### Integration
- Provide documented CLI commands and REST endpoints so RevOps automation can invoke enrichments and pull persona payloads programmatically.
- Reporting output must support Markdown and PDF exports so teams can drop artifacts into Confluence, Slides, or CRM attachments.

---

_This PRD captures the essence of WAF Security._

_Created through collaborative discovery between Compa and AI facilitator._

---

## PRD Summary
- Executive summary + differentiation captured for WAFtotal + GTM Radar insight spine.
- SaaS B2B classification with medium complexity; references to product brief and research artifacts.
- MVP/growth/vision scope defined along with SaaS-specific requirements and innovation patterns.
- 25 functional requirements plus targeted NFRs (performance, security, scalability, integration).

## Product Value Summary
WAF Security converts raw WAF/CDN telemetry into persona-ready narratives and vendor-agnostic transparency so GTM, security, and architecture teams can act with confidence, differentiate against incumbents, and accelerate every conversation with evidence in minutes.

