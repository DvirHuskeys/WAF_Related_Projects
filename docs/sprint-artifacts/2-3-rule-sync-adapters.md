# Story 2.3: Rule Sync Adapter Framework

Status: review

## Story

As a platform engineer,  
I want the rule-sync CLI to load vendor exports through pluggable adapters,  
so new managed-rule packs can be normalized without touching persona or reporting code.

## Acceptance Criteria

1. Given I run `python scripts/rule_sync/run.py cloudflare --source data/rules/cloudflare_sample.json`, the CLI loads the adapter module (`scripts/rule_sync/cloudflare.py`), parses the JSON, and inserts/updates rows in DuckDB `managed_rules` with vendor/name/category/severity/detection_pattern/metadata fields.  
2. Adapters follow a documented interface: exporting a `load_rules(Path) -> List[dict]` with required keys, raising clear exceptions on parse failures.  
3. Adding a new adapter (e.g., `aws_waf.py`) requires only dropping the file into `scripts/rule_sync/` and referencing it via CLI `--vendor aws_waf`; no changes to persona/reporting modules.  
4. CLI outputs summary counts per vendor (inserted, updated) and references the job log entry (Story 2.4).  
5. README/Makefile include instructions for running rule sync with different vendors.

## Tasks / Subtasks

- [x] Implement adapter loader (AC: 1–3)  
  - [x] Dynamically import `scripts.rule_sync.<vendor>` and call `load_rules(source_path)`.  
  - [x] Validate each rule dict contains required keys; raise `typer.BadParameter` if unknown vendor.  
- [x] Cloudflare adapter polishing (AC: 1)  
  - [x] Ensured existing `cloudflare.py` returns normalized dicts with `metadata`.  
- [x] CLI UX (AC: 4 & 5)  
  - [x] Add summary stats + job logging hook.  
  - [x] Update README and `Makefile` target `rule-sync`.  
- [x] Extension doc (AC: 3)  
  - [x] Added `docs/adapters.md` describing adapter contract.

## Dev Notes

- Aligns with PRD FR3, FR20.  
- Reuse DuckDB helper functions; wrap inserts in transactions.  
- Consider optionally supporting zipped/vendor-provided formats later.

### Project Structure Notes

- Adapters live under `scripts/rule_sync/`.  
- CLI stays thin, delegating parsing to adapters.  
- Ensure `__init__.py` exports available vendors for discovery.

### References

- [Source: docs/epics.md#story-23-rule-sync-adapter-framework]  
- [Source: docs/prd.md#functional-requirements FR3, FR20]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/2-3-rule-sync-adapters.context.xml


### Agent Model Used

GPT-5.1 Codex

### Debug Log References

- 2025-11-30: Implemented dynamic adapter loader + rule validation, supporting drop-in vendor modules.  
- 2025-11-30: Added summary output and Makefile/README coverage; documented adapter contract in `docs/adapters.md`.  
- 2025-11-30: Ran `python scripts/rule_sync/run.py cloudflare --source data/rules/cloudflare_sample.json` followed by `make test`.

### Completion Notes List

- CLI now reports inserted/updated counts, job IDs, and handles unknown vendors gracefully.  
- Deleting + inserting ensures idempotent sync without requiring DuckDB PKs.  
- Developers can add new adapters by creating `scripts/rule_sync/<vendor>.py` thanks to the dynamic resolver.

### File List

- `scripts/rule_sync/__init__.py`
- `scripts/rule_sync/run.py`
- `docs/adapters.md`
- `README.md`
- `Makefile`
- `tests/test_rule_sync.py`
- `docs/sprint-artifacts/sprint-status.yaml`

## Change Log

- 2025-11-30: Delivered adapter framework, documentation, and CLI UX for rule sync; story ready for review.
