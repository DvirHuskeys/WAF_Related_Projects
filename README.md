# WAF Security Local Lab

A local-first sandbox for exploring two complementary ideas:

- **WAFtotal** – reverse engineer managed rules, normalize them, and present vendor-agnostic comparisons that marketing and GTM teams can use instantly.
- **GTM Radar** – enrich domain lists to detect existing WAF/CDN stacks, infer likely pain points (config drift, downtime risk, attack mix), and auto-generate story prompts for sales.

This repository intentionally favors scrappy velocity over production hardening. Everything can run offline on a single laptop via simple Python scripts and Streamlit/FastAPI apps.

## Getting Started

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a domain seed file (or use `data/samples/domains.csv`) and run:

```bash
python scripts/domain_enrich.py data/samples/domains.csv
python scripts/rule_sync/run.py --vendor cloudflare --source data/rules/cloudflare_sample.json
uvicorn backend.main:app --reload
streamlit run ui/app.py
```

Refer to `docs/architecture.md` for the module breakdown and `docs/playbook/story-prompts.md` for persona-driven story hooks.

## Testing

```bash
python -m pytest
```

See `docs/testing.md` for the manual smoke checklist.

