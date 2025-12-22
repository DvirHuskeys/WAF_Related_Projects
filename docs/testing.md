# Testing Journal

Use this log to record manual verification steps. Template:

```
## YYYY-MM-DD
- [ ] domain_enrich.py run
  Command: python scripts/domain_enrich.py data/samples/domains.csv
  Result: (paste summary)
- [ ] rule_sync/run.py
  Command: python scripts/rule_sync/run.py --vendor cloudflare
  Result:
- [ ] API healthcheck
  Command: curl http://localhost:8000/health
  Result:
- [ ] Streamlit smoke
  Notes:
```

Automated checks live under `tests/`. Run them with `pytest`.

---

## 2025-11-30
- [x] domain_enrich.py run  
  Command: `python scripts/domain_enrich.py data/samples/domains.csv`  
  Result: Generated four enriched records in DuckDB, offline heuristics used.
- [x] rule_sync/run.py  
  Command: `python scripts/rule_sync/run.py cloudflare --source data/rules/cloudflare_sample.json`  
  Result: Loaded two sample managed rules.
- [x] API schema test  
  Command: `python -m pytest tests/test_schema.py`  
  Result: Passed (ensures DuckDB tables exist).

