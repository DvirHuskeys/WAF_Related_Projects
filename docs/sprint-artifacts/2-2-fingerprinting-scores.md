# Story 2.2: Fingerprinting & Scoring Pipeline

Status: review

## Story

As the enrichment job,  
I want to detect WAF/CDN stacks and generate drift/downtime/attack scores,  
so that persona and reporting modules have consistent telemetry to work with.

## Acceptance Criteria

1. Given a domain row processed by Story 2.1, when fingerprinting runs then `detected_waf`, `detected_cdn`, `config_drift_score`, `downtime_risk_score`, `attack_surface_score`, `last_observed`, and raw JSON are persisted in DuckDB.  
2. The pipeline honors env toggle `USE_WAFW00F=1` to use real wafw00f detection; when disabled, a deterministic fallback (seeded random) is used so offline runs are predictable.  
3. Errors from wafw00f or network failures are caught and logged; processing continues for remaining domains.  
4. Scoring heuristic ensures values are normalized between 0.0–1.0 and can be tuned centrally (e.g., `scoring.py`).  
5. CLI output shows per-domain summary (e.g., “example.com → cloudflare/cloudflare drift 0.74”) and references the job ID from Story 2.4.

## Tasks / Subtasks

- [x] Implement fingerprinting helper (AC: 1–2)  
  - [x] Update `backend/services/fingerprint.py` to wrap wafw00f with timeout + fallback.  
  - [x] Add deterministic seed when fallback is used.  
- [x] Scoring logic (AC: 1 & 4)  
  - [x] `backend/services/scoring.py` now computes reproducible scores + priority index.  
  - [x] Documented CLI usage in README; heuristics live centrally.  
- [x] Integrate into CLI (AC: 1,3,5)  
  - [x] Enrichment CLI calls fingerprint/scoring and logs per-domain summary.  
  - [x] Errors are caught and warnings emitted while continuing.  
- [x] Tests / smoke (AC: 2,4)  
  - [x] Regression suite covers validation helpers; manual runs verify deterministic offline behavior.

## Dev Notes

- Aligns with PRD FR2 + FR4 and architecture Section 2 (duckdb data flow).  
- Consider hooking into job logging table once Story 2.4 is complete.  
- Keep heuristics accessible for future tuning (maybe YAML config).

### Project Structure Notes

- Functions belong under `backend/services/`; CLI should import them rather than duplicating logic.  
- No new directories needed.

### References

- [Source: docs/epics.md#story-22-fingerprinting--scoring-pipeline]  
- [Source: docs/prd.md#functional-requirements FR2–FR4]  
- [Source: docs/architecture.md#2-architecture-overview]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/2-2-fingerprinting-scores.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Instrumented fingerprint fallback with domain-seeded randomness; `USE_WAFW00F` still toggles real detection.  
- 2025-11-30: Refactored scoring to generate deterministic 0–1 heuristics plus priority index and integrated them into the enrichment CLI output.  
- 2025-11-30: Ran `python scripts/domain_enrich.py ...` (dry-run + live) and `make test`.

### Completion Notes List

- CLI now prints `{domain} → WAF/CDN drift X.XX` per domain, honoring dry-run, limit, error handling, and job IDs.  
- Scores are deterministic offline but still reflect WAF-specific weighting.  
- README documents the CLI; sprint status + story marked ready for review.

### File List

- `backend/services/fingerprint.py`
- `backend/services/scoring.py`
- `scripts/domain_enrich.py`
- `README.md`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Completed fingerprinting/scoring pipeline integration; story ready for review.
