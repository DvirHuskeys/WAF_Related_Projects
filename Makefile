SHELL := /bin/bash
PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
STREAMLIT_SERVER_PORT ?= 8501
STREAMLIT_HEADLESS ?= true
FASTAPI_HOST ?= 127.0.0.1
FASTAPI_PORT ?= 8000

.PHONY: help bootstrap venv install env init-db seed-sample-data domain-enrich rule-sync export-domains export-rules export-usage run-ui api test lint clean

help:
	@grep -E '^[a-zA-Z_-]+:' Makefile | awk -F':' '{printf "\033[36m%-12s\033[0m %s\n", $$1, $$2}'

venv:
	@if [ ! -d "$(VENV)" ]; then \
		$(PYTHON) -m venv $(VENV); \
		printf '\n[venv] Created $(VENV)\n'; \
	fi

install: venv
	@$(PIP) install --upgrade pip
	@$(PIP) install -r requirements.txt

bootstrap: install
	@echo "Environment ready. Activate with: source $(VENV)/bin/activate"

env:
	@cp -n .env.example .env 2>/dev/null || true
	@echo "Review .env to customize USE_WAFW00F, ports, and paths."

init-db: install
	@source $(VENV)/bin/activate && python scripts/init_duckdb.py

seed-sample-data: install
	@source $(VENV)/bin/activate && python scripts/seed_sample_data.py

domain-enrich: install
	@source $(VENV)/bin/activate && python scripts/domain_enrich.py data/samples/domains.csv

rule-sync: install
	@source $(VENV)/bin/activate && python scripts/rule_sync/run.py cloudflare --source data/rules/cloudflare_sample.json

export-domains: install
	@source $(VENV)/bin/activate && python scripts/export_data.py --domains --format csv

export-rules: install
	@source $(VENV)/bin/activate && python scripts/export_data.py --rules --format csv

export-usage: install
	@source $(VENV)/bin/activate && python scripts/export_data.py --usage --format csv

run-ui: install
	@source $(VENV)/bin/activate && \
	STREAMLIT_HEADLESS=$(STREAMLIT_HEADLESS) \
	STREAMLIT_SERVER_PORT=$(STREAMLIT_SERVER_PORT) \
	streamlit run ui/app.py --server.port $(STREAMLIT_SERVER_PORT)

api: install
	@source $(VENV)/bin/activate && \
	uvicorn backend.main:app --host $(FASTAPI_HOST) --port $(FASTAPI_PORT)

test: install
	@source $(VENV)/bin/activate && pytest -q

lint: install
	@source $(VENV)/bin/activate && python -m compileall backend scripts ui

clean:
	rm -rf $(VENV) __pycache__ .pytest_cache .ruff_cache
