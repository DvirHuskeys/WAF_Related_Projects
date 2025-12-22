# Story 6.4: Adapter Interface Contract

Status: ready-for-dev

## Story

As future developers (or partners),  
we want a documented adapter contract and template,  
so new vendor rule packs can be added quickly without reverse-engineering existing code.

## Acceptance Criteria

1. Create `docs/adapters.md` (or similar) explaining the adapter interface: required function signature (`load_rules(Path) -> List[dict]`), required keys, metadata expectations, error handling, logging guidelines.  
2. Provide `scripts/rule_sync/adapter_template.py` that developers can copy to create new adapters.  
3. CLI automatically discovers adapters in `scripts/rule_sync/` (maybe via entrypoint list or glob) and lists available vendors when `--list` is passed.  
4. README references the doc/template and instructs how to add vendor exports.  
5. Contract includes guidance on storing source/synced_at fields to satisfy Story 4.4.

## Tasks / Subtasks

- [ ] Documentation (AC: 1 & 4)  
  - [ ] Write `docs/adapters.md` with interface description + examples.  
  - [ ] Update README with quick instructions.  
- [ ] Template file (AC: 2)  
  - [ ] Add `adapter_template.py` with comments guiding implementers.  
- [ ] CLI discovery (AC: 3)  
  - [ ] Add `--list` flag and dynamic discovery logic (glob modules).  
- [ ] Source metadata guidance (AC: 5)  
  - [ ] Emphasize setting `source` and `synced_at`.

## Dev Notes

- Supports FR20; reduces friction when adding AWS/Akamai.  
- Template should mention best practices (validation, logging).

### Project Structure Notes

- Keep templates outside runtime modules to avoid importing them accidentally.

### References

- [Source: docs/epics.md#story-64-adapter-interface-contract]  
- [Source: docs/prd.md#functional-requirements FR20]

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/6-4-adapter-interface-contract.context.xml


### Agent Model Used

_TBD during implementation_

### Debug Log References

### Completion Notes List

### File List

