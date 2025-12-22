# Product Brief: WAF Security

**Date:** 2025-11-30
**Author:** Compa
**Context:** Greenfield BMad Method initiative

---

## Executive Summary

WAF Security is building an internal “insight spine” that fuses two sibling ideas—**WAFtotal**, a vendor-agnostic managed-rule transparency experience, and **GTM Radar**, a domain fingerprinting + storytelling engine for sales and marketing teams. Together they deliver three promises: (1) decode any prospect’s WAF/CDN posture in minutes, (2) expose cross-vendor rule deltas so CISOs can trust the narrative, and (3) auto-generate pitch angles and executive briefs grounded in live telemetry rather than vibes.

---

## Core Vision

### Problem Statement

Security and GTM teams at mid-to-large enterprises cannot easily see what managed rules are actually protecting their prospects (or their own estates). Each WAF/CDN vendor ships opaque rule packs, telemetry is siloed, and RevOps teams resort to guessing which pain story (downtime, drift, bot pressure) will resonate. This leads to configuration drift, renewal risk, and generic pitches that fail to differentiate against Cloudflare/Akamai/F5 narratives.

### Proposed Solution

Create a local-first lab that ingests domain signals, normalizes vendor rule metadata, and turns everything into human-ready assets: GTM Radar scores, Rule Transparency cards, and executive-ready briefs. The lab runs via FastAPI + DuckDB + Streamlit so we can iterate quickly, and it exposes APIs/CLI endpoints for AE Alex, CISO Cassandra, and Platform Winston personas to self-serve insights before every conversation.

### Initial Vision Highlights

- Dual-track architecture where intel harvesting (domain enrich + rule sync) feeds both GTM tooling and marketing content.
- Vendor-agnostic rule explorer that lets us remix Cloudflare/AWS/Akamai logic without touching production stacks.
- Persona-aware outputs (pitch prompts, board slides, architectural comparisons) instead of static dashboards.

---

## Target Users

### Primary Users

- **AE Alex / RevOps Riley** – need prioritized outreach plans plus “hook” narratives tied to the domain’s detected posture. They currently rely on spreadsheet heuristics, so a single GTM Radar card that screams “config drift high, lead with coherence” lets them open conversations with authority.
- **CISO Cassandra / Platform Architect Winston** – want proof that rule coverage is complete, portable, and up to date before renewals or migrations. Today they juggle Cloudflare dashboards, AWS JSON exports, and PDF pen tests; WAFtotal gives them a side-by-side rule explorer plus executive-ready writeups they can drop into board decks without touching live configs.

### Secondary Users

- **Security Marketing + Campaign teams** – repackage Rule Remix insights into webinars, blog posts, and enablement collateral.
- **MSSP / Partner overlays** – differentiate their services with neutral, vendor-agnostic storytelling.

### User Journey

1. AE Alex uploads a prospect CSV → GTM Radar enriches domains → Streamlit shows drift/downtime/attack risk plus a ready-made opener.
2. Before an executive review, CISO Cassandra opens WAFtotal → compares Cloudflare managed rules vs. AWS WAF pack → exports the Rule Transparency storyboard into her deck.
3. Marketing pulls the same rule cards into a “Rule Remix” landing page, ensuring every outbound campaign is grounded in live data.

---

## MVP Scope

### Core Features

1. **Domain Enrichment CLI & Service** – ingest CSVs, detect WAF/CDN, score drift/downtime/attack-surface.
2. **Rule Library Normalizer** – adapters per vendor, schema stored in DuckDB with freshness metadata.
3. **Persona API + Streamlit UI** – `/persona/{id}/{domain}` responses and a lightweight UI that surfaces stack snapshot + story prompt.
4. **Reporting Templates** – auto-generate GTM one-pagers and executive briefs referencing latest data.

### Future Vision

- Automated Rule Remix lab for side-by-side rule translation.
- Threat rehearsal animations for marketing launches.
- Integration with CRM to auto-attach GTM Radar intel to target accounts.

---

## Success Metrics

- **Adoption:** Number of enriched domains per week (target 100+) and count of persona API calls.
- **Impact:** % of outbound sequences using GTM Radar prompts; win-rate lift on opportunities tagged with WAFtotal intel.
- **Quality:** Rule library freshness (days since last vendor sync) and coverage breadth (vendors × categories).

### Business Objectives

- Shorten discovery cycles for GTM teams by giving them authoritative pain narratives.
- Improve renewal/expansion conversations with vendor-agnostic evidence.
- Build a reusable insight backbone that future PRDs, campaigns, and architecture decisions can reference.

### Key Performance Indicators

1. **Intel Freshness SLA:** 95% of rule entries <30 days old.
2. **Persona Usage:** 60% of active opportunities attach at least one persona story prompt.
3. **Pipeline Influence:** 25% of closed-won deals cite GTM Radar insight.

---

## MVP Scope (continued)

---

## Market Context

- WAF spend projected to hit USD 19–29 B within a decade (sources: SNS Insider, ResearchAndMarkets; see `docs/research-market-2025-11-30.md`).
- NA + EMEA regulated industries represent ~USD 7.9 B SAM with BFSI/retail/healthcare leading adoption.
- Machine-learning WAF features and API protection are the top procurement criteria, creating urgency for transparent rule storytelling.

## Technical Preferences

- Python-based stack (FastAPI, Typer, DuckDB, Streamlit) for rapid iteration and local/offline usage.
- Modular rule adapters per vendor; CLI commands for enrichment/rule sync; persona service for future GraphQL/REST exposure.
- Keep data storage pluggable so we can graduate from DuckDB to Postgres without rewriting business logic.

## Organizational Context

- Internal enablement tool spanning Security, PMM, RevOps, and Architecture teams.
- Needs to plug into existing research (brainstorm + market study) and pave the way for PRD, architecture, and later sprint planning workflows.
- No external customer commitments yet; we control cadence and scope.

## Risks and Assumptions

| Risk | Mitigation |
| --- | --- |
| Vendor pushback on rule transparency | Use public docs + customer-provided exports; position as advisory. |
| Data freshness stagnates | Automate monthly syncs; log provenance/freshness in DuckDB. |
| GTM adoption lag | Embed prompts into CRM/email templates; track usage KPIs. |
| Security team overlap | Clarify that this supplements, not replaces, enforcement tooling. |

## Supporting Materials

- Brainstorm session: `docs/brainstorming-session-results-2025-11-30.md`
- Market/domain research: `docs/research-market-2025-11-30.md`
- Source DuckDB schema + scripts in repo (`scripts/domain_enrich.py`, `scripts/rule_sync/…`)

---

_This Product Brief captures the vision and requirements for WAF Security._

_It was created through collaborative discovery and reflects the unique needs of this Greenfield BMad Method initiative project._

_Next: Use the PRD workflow to create detailed product requirements from this brief._

