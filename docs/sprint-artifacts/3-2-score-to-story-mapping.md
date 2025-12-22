# Story 3.2: Score-to-Story Mapping

Status: review

## Story

As AE Alex,  
I want persona prompts tailored to score ranges (drift, downtime, attack surface),  
so I can lead every outreach with the most relevant pain story.

## Acceptance Criteria

1. Given scoring thresholds are defined (e.g., drift >0.7), when persona service builds a prompt it uses the matching hook text (“Lead with configuration coherence”) from a central configuration file.  
2. Hooks are customizable per persona (AE Alex, CISO Cassandra, Platform Winston) and stored in a data-driven structure (YAML/JSON or Python dict).  
3. Persona API response includes both a single `story_prompt` (string) and structured `hooks` array (each with `title`, `description`, `score_reason`).  
4. Streamlit persona cards display the primary hook plus badges for other applicable hooks; copy button includes the top hook.  
5. README or config file documents how to adjust thresholds and hook text.

## Tasks / Subtasks

- [x] Hook configuration (AC: 1–2,5)  
  - [x] Added `config/persona_hooks.yaml` + loader for thresholds/hooks; documented in README.  
- [x] Persona service integration (AC: 1–3)  
  - [x] `backend/services/scoring.py` selects hooks per persona and returns structured array consumed by persona API/UI.  
- [x] UI wiring (AC: 4)  
  - [x] Persona cards display hook badges; `story_prompt` includes leading hook copy.  
- [x] Documentation (AC: 5)  
  - [x] README notes where to edit `persona_hooks.yaml`.

## Dev Notes

- Hooks should match UX copy guidelines; keep language short and action-oriented.  
- Consider weighting scores if multiple thresholds trigger simultaneously (e.g., drift high + downtime medium).  
- Provide tests verifying config parsing + deterministic output.

### Project Structure Notes

- Place config under `config/` and expose via `backend/services/hooks.py`.  
- Ensure changes don’t require app restart (reload on change optional).

### References

- [Source: docs/epics.md#story-32-score-to-story-mapping]  
- [Source: docs/prd.md#functional-requirements FR6, FR23]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/3-2-score-to-story-mapping.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Added persona hook config + loader, updated scoring + persona service to output hooks & warnings for API/UI.  
- 2025-11-30: Streamlit persona cards now show hook badges, tapping data from API.  
- 2025-11-30: `make test` (15 passed).

### Completion Notes List

- Score thresholds and copy live in `config/persona_hooks.yaml` enabling simple future tweaks.  
- Persona API + UI share structured `hooks` array, delivering consistent prompts and badges.  
- Documentation highlights how to customize persona messaging.

### File List

- `config/persona_hooks.yaml`
- `backend/services/hooks.py`
- `backend/services/scoring.py`
- `backend/services/persona.py`
- `ui/app.py`
- `README.md`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Implemented score-driven persona hook mapping across API/UI; story ready for review.
