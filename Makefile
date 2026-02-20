.PHONY: help install install-dev test test-cov lint format typecheck check clean fetch-catalog catalog-info build publish scan

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Setup ──────────────────────────────────────────────
install: ## Install ControlGate
	python3 -m pip install .

install-dev: ## Install with dev dependencies
	python3 -m pip install -e ".[dev]"
	pre-commit install

# ─── Testing ────────────────────────────────────────────
test: ## Run tests
	python3 -m pytest tests/ -v

test-cov: ## Run tests with coverage report
	python3 -m pytest tests/ -v --cov=controlgate --cov-report=term-missing --cov-report=html

# ─── Code Quality ──────────────────────────────────────
lint: ## Run linter (ruff)
	python3 -m ruff check src/ tests/

format: ## Auto-format code (ruff)
	python3 -m ruff format src/ tests/
	python3 -m ruff check --fix src/ tests/

typecheck: ## Run type checker (mypy)
	python3 -m mypy src/controlgate/

check: lint typecheck test ## Run all checks (lint + typecheck + test)

# ─── Build & Publish ───────────────────────────────────
clean: ## Clean build artifacts
	rm -rf dist/ build/ *.egg-info src/*.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build: clean fetch-catalog ## Build distribution packages
	python3 -m build

publish: build ## Publish to PyPI (requires PYPI_TOKEN)
	python3 -m twine upload dist/*

# ─── ControlGate Usage ─────────────────────────────────
scan: ## Run ControlGate scan on staged changes
	python3 -m controlgate scan --mode pre-commit --format markdown

scan-pr: ## Run ControlGate scan in PR mode
	python3 -m controlgate scan --mode pr --format markdown

fetch-catalog: ## Download latest NIST catalog from NCSB
	python3 -m controlgate update-catalog

catalog-info: ## Show current catalog version info
	python3 -m controlgate catalog-info
