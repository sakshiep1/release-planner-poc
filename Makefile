.PHONY: dev backend frontend install-backend install-frontend install help test

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install-backend: ## Install Python backend dependencies
	pip install -r requirements.txt

install-frontend: ## Install frontend npm dependencies
	cd web && npm install

install: install-backend install-frontend ## Install all dependencies

backend: ## Start FastAPI backend with hot reload
	uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

frontend: ## Start Vite dev server
	cd web && npm run dev

dev: ## Start both backend and frontend concurrently
	@echo "Starting backend on :8000 and frontend on :5173"
	@(uvicorn src.main:app --reload --host 0.0.0.0 --port 8000 &) && cd web && npm run dev

test: ## Run Python tests
	python -m pytest tests/ -v

cli-import: ## Import cached CVE evidence
	python -m src.cli.main import $(EVIDENCE_PATH)

cli-run: ## Run full pipeline
	python -m src.cli.main run

cli-report: ## Generate markdown report
	python -m src.cli.main report --output release-plan.md
