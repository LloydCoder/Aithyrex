.PHONY: dev test demo lint migrate shell clean

# ── Development ───────────────────────────────────────────────────────────────
dev:
	@echo "🛡️  Starting Aithyrex development environment..."
	docker compose up --build

dev-bg:
	docker compose up --build -d
	@echo "✅ Running in background. Logs: make logs"

logs:
	docker compose logs -f api

stop:
	docker compose down

clean:
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true

# ── Database ──────────────────────────────────────────────────────────────────
migrate:
	@echo "→ Running Alembic migrations..."
	alembic upgrade head

migrate-down:
	alembic downgrade -1

shell-db:
	docker compose exec postgres psql -U aithyrex -d aithyrex

# ── Testing ───────────────────────────────────────────────────────────────────
test:
	@echo "→ Running unit tests..."
	python -m pytest backend/tests/unit/ -v --tb=short

test-integration:
	@echo "→ Running integration tests (requires live services)..."
	python -m pytest backend/tests/integration/ -v --tb=short

test-all:
	python -m pytest backend/tests/ -v --tb=short

test-cov:
	python -m pytest backend/tests/unit/ --cov=backend --cov-report=term-missing --cov-report=html
	@echo "→ Coverage report: htmlcov/index.html"

# ── Sprint 1 Demo ─────────────────────────────────────────────────────────────
demo:
	@echo "🛡️  Aithyrex — Sprint 1 Demo"
	@echo "================================"
	bash scripts/demo.sh

# ── Code quality ─────────────────────────────────────────────────────────────
lint:
	ruff check backend/
	@echo "✅ Lint passed"

format:
	ruff format backend/

typecheck:
	mypy backend/ --ignore-missing-imports

security:
	bandit -r backend/ -ll -x backend/tests/

# ── API (local, no Docker) ────────────────────────────────────────────────────
run:
	uvicorn backend.main:app --host 0.0.0.0 --port 8002 --reload

# ── Frontend ─────────────────────────────────────────────────────────────────
frontend-install:
	cd frontend && npm install

frontend-dev:
	cd frontend && npm run dev

frontend-build:
	cd frontend && npm run build

frontend-type-check:
	cd frontend && npm run type-check

# ── Full stack ────────────────────────────────────────────────────────────────
fullstack:
	@echo "Starting full stack (Docker backend + Next.js frontend)..."
	docker compose up -d
	cd frontend && npm run dev

# ── Help ─────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "Aithyrex — Available commands:"
	@echo ""
	@echo "  make dev          Start full dev environment (Docker)"
	@echo "  make test         Run unit tests"
	@echo "  make demo         Run Sprint 1 demo (needs dev running)"
	@echo "  make migrate      Run DB migrations"
	@echo "  make lint         Ruff lint check"
	@echo "  make clean        Remove containers + cache"
	@echo ""
