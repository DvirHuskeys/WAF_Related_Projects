# Story 2.2: Fingerprinting & Scoring Pipeline

Status: drafted

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

- [ ] Implement fingerprinting helper (AC: 1–2)  
  - [ ] Update `backend/services/fingerprint.py` to wrap wafw00f with timeout + fallback.  
  - [ ] Add deterministic seed when fallback is used.  
- [ ] Scoring logic (AC: 1 & 4)  
  - [ ] Create `backend/services/scoring.py` with configurable thresholds.  
  - [ ] Document how to adjust heuristics in README.  
- [ ] Integrate into CLI (AC: 1,3,5)  
  - [ ] Enrichment CLI (Story 2.1) calls fingerprint/scoring and writes values.  
  - [ ] Log per-domain summary + warnings; continue on errors.  
- [ ] Tests / smoke (AC: 2,4)  
  - [ ] Add quick unit tests or notebook verifying outputs between 0–1.  
  - [ ] Verify fallback path returns consistent values across runs.

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

<!-- story-context XML placeholder -->

### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

