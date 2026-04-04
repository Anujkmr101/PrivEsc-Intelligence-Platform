# PIP — PrivEsc Intelligence Platform
# Makefile for common development and CI tasks.
# Run `make help` to see all available targets.

.PHONY: help install install-dev test test-unit test-integration lint fmt typecheck \
        security-lint clean update-kb docker docker-run api docs

PYTHON   := python3
PIP      := pip
PYTEST   := pytest
RUFF     := ruff
MYPY     := mypy
BANDIT   := bandit
DOCKER   := docker
IMAGE    := pip-toolkit
VERSION  := 2.0.0

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "PIP — PrivEsc Intelligence Platform $(VERSION)"
	@echo "────────────────────────────────────────────────"
	@echo ""
	@echo "Setup:"
	@echo "  make install        Install runtime dependencies"
	@echo "  make install-dev    Install all dev + test dependencies"
	@echo ""
	@echo "Quality:"
	@echo "  make test           Run full test suite with coverage"
	@echo "  make test-unit      Run unit tests only"
	@echo "  make test-int       Run integration tests only"
	@echo "  make lint           Run ruff linter"
	@echo "  make fmt            Auto-format with ruff"
	@echo "  make typecheck      Run mypy type checker"
	@echo "  make security-lint  Run bandit security linter"
	@echo "  make check          Run all quality checks"
	@echo ""
	@echo "Runtime:"
	@echo "  make scan           Quick local scan (read-only)"
	@echo "  make api            Start REST API server (dev mode)"
	@echo "  make update-kb      Sync knowledge base (GTFOBins, NVD)"
	@echo ""
	@echo "Docker:"
	@echo "  make docker         Build Docker image"
	@echo "  make docker-run     Run scan via Docker"
	@echo ""
	@echo "Misc:"
	@echo "  make clean          Remove build artifacts and caches"
	@echo "  make docs           Open documentation"
	@echo ""

# ── Setup ─────────────────────────────────────────────────────────────────────
install:
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements-dev.txt

# ── Testing ───────────────────────────────────────────────────────────────────
test:
	$(PYTEST) tests/ -v \
		--tb=short \
		--cov=pip \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		--cov-fail-under=60

test-unit:
	$(PYTEST) tests/test_models.py tests/test_scoring.py tests/test_core.py -v

test-int:
	$(PYTEST) tests/test_integration.py -v

test-fast:
	$(PYTEST) tests/ -x --tb=short -q

# ── Code quality ──────────────────────────────────────────────────────────────
lint:
	$(RUFF) check pip/ tests/ plugins/

fmt:
	$(RUFF) format pip/ tests/ plugins/
	$(RUFF) check --fix pip/ tests/ plugins/

typecheck:
	$(MYPY) pip/ --ignore-missing-imports

security-lint:
	$(BANDIT) -r pip/ -ll \
		--exclude pip/api/,pip/core/shell_compat.py \
		-f txt

check: lint typecheck security-lint test
	@echo ""
	@echo "✓ All checks passed."

# ── Runtime ───────────────────────────────────────────────────────────────────
scan:
	$(PYTHON) pip.py scan --mode quick --stealth normal

scan-deep:
	$(PYTHON) pip.py scan --mode deep --report all --mitre-map --blue-team

api:
	$(PYTHON) pip.py serve --host 127.0.0.1 --port 8443 --auth none --reload

update-kb:
	$(PYTHON) pip.py update

plugins-list:
	$(PYTHON) pip.py plugins

# ── Docker ────────────────────────────────────────────────────────────────────
docker:
	$(DOCKER) build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

docker-run:
	$(DOCKER) run --rm -it \
		-v $(PWD)/pip-output:/output \
		$(IMAGE):$(VERSION) scan --mode quick --output /output

docker-api:
	$(DOCKER) run --rm -d \
		-p 8443:8443 \
		-e PIP_JWT_SECRET=$${PIP_JWT_SECRET:-changeme} \
		-v $(PWD)/pip-output:/output \
		--name pip-api \
		$(IMAGE):$(VERSION) serve --host 0.0.0.0 --port 8443

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	rm -rf .pytest_cache .coverage htmlcov .mypy_cache .ruff_cache
	rm -rf dist/ build/ *.egg-info
	@echo "Clean complete."

# ── Docs ─────────────────────────────────────────────────────────────────────
docs:
	@echo "Opening documentation..."
	@open docs/index.md 2>/dev/null || xdg-open docs/index.md 2>/dev/null || \
		echo "Open docs/index.md manually."
