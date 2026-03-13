.PHONY: help setup dev-up dev-down migrate migrate-down seed test test-cov lint format clean check-db

# ── Detect venv python ─────────────────────────────────────────────────────────
PYTHON := $(shell [ -f .venv/bin/python ] && echo .venv/bin/python || echo python3)
PIP    := $(shell [ -f .venv/bin/pip ]    && echo .venv/bin/pip    || echo pip3)

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ── Setup ──────────────────────────────────────────────────────────────────────
setup: ## Create venv and install all dependencies
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "✅  Setup complete. Activate with: source .venv/bin/activate"

# ── Docker ─────────────────────────────────────────────────────────────────────
up: ## Start PostgreSQL only (production-like, no pgAdmin)
	docker compose up -d postgres
	@echo "✅  PostgreSQL  → localhost:5432"
dev-up: ## Start PostgreSQL + pgAdmin (profile: dev)
	docker compose --profile dev up -d
	@echo "✅  PostgreSQL  → localhost:5432"
	@echo "✅  pgAdmin     → http://localhost:5050 


dev-down: ## Stop and remove all containers
	docker compose --profile dev down

down: ## Stop all containers (keep volumes)
	docker compose down

nuke: ## ⚠ Stop all containers AND delete volumes (DATA LOSS)
	@read -p "⚠  This will DELETE all database data. Type 'yes' to confirm: " yn; \
	[ "$$yn" = "yes" ] || exit 1
	docker compose --profile dev down -v

# ── Database ───────────────────────────────────────────────────────────────────
migrate: ## Apply all pending Alembic migrations
	$(PYTHON) -m alembic upgrade head

migrate-down: ## Rollback the last Alembic migration
	$(PYTHON) -m alembic downgrade -1

migrate-status: ## Show current migration revision
	$(PYTHON) -m alembic current

migrate-history: ## Show full migration history
	$(PYTHON) -m alembic history --verbose

check-db: ## Verify database connection
	$(PYTHON) -c "import logging; logging.basicConfig(level=logging.INFO); from database.connection import check_connection; check_connection()"

seed: ## Load baseline CMDB assets (linked to Wazuh agent IDs)
	$(PYTHON) -m ingestion.asset_registry seed

# ── Testing ────────────────────────────────────────────────────────────────────
test: ## Run the full test suite
	$(PYTHON) -m pytest tests/ -v

test-cov: ## Run tests with HTML coverage report
	$(PYTHON) -m pytest tests/ -v --cov=. --cov-report=html --cov-report=term-missing
	@echo "📊  Coverage report → htmlcov/index.html"

test-fast: ## Run tests, stop on first failure
	$(PYTHON) -m pytest tests/ -x -v

# ── Code Quality ───────────────────────────────────────────────────────────────
lint: ## Run ruff linter
	$(PYTHON) -m ruff check .

format: ## Auto-fix ruff lint issues & format code
	$(PYTHON) -m ruff check . --fix
	$(PYTHON) -m ruff format .

# ── Utilities ──────────────────────────────────────────────────────────────────
clean: ## Remove all cache and generated files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .coverage htmlcov/ .pytest_cache/ dist/ build/ *.egg-info/
	@echo "✅  Clean complete."
