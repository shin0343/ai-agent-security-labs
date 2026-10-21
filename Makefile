SHELL := /bin/bash
.DEFAULT_GOAL := help

PYTHON ?= python3
VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
EVAL_DIR ?= run/eval

# The inherited macOS environment in this workspace can point PYTHONHOME at a
# different installation. Every project command clears it.
RUN_PY := env -u PYTHONHOME -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 $(PY)
RUN_PIP := env -u PYTHONHOME -u PYTHONPATH $(PIP)

.PHONY: help setup build demo test lint e2e e2e-webkit screenshots eval verify clean

help:
	@echo "Agent Security Workbench"
	@echo ""
	@echo "  make setup        Create .venv, install pinned dependencies, build the UI"
	@echo "  make demo         Serve the built workbench at http://127.0.0.1:8765"
	@echo "  make test         Run the Python regression and security suite"
	@echo "  make lint         Ruff, mypy and frontend ESLint"
	@echo "  make e2e          Run the Playwright analyst workflow against a fresh DB"
	@echo "  make e2e-webkit   Run the same workflow in Playwright WebKit (install engine first)"
	@echo "  make build        Type-check and build the React frontend"
	@echo "  make eval         Run the synthetic evaluation into $(EVAL_DIR)"
	@echo "  make verify       Build, test, lint and run browser E2E"
	@echo "  make screenshots  Capture docs/screenshots from the E2E flow"
	@echo "  make clean        Remove generated build/test caches (not run/ data)"

setup:
	@if [ ! -x "$(PY)" ]; then env -u PYTHONHOME -u PYTHONPATH "$(PYTHON)" -m venv "$(VENV)"; fi
	$(RUN_PIP) install -r requirements-dev.txt -c constraints.txt
	cd frontend && npm ci
	cd frontend && npm run build
	@echo "Setup complete. Run 'make demo'."

build:
	cd frontend && npm run build

demo:
	@test -f frontend/dist/index.html || { echo "Frontend build missing. Run 'make setup' first."; exit 1; }
	$(RUN_PY) -m agentguard.workbench.api

test:
	$(RUN_PY) -m pytest -q

lint:
	$(RUN_PY) -m ruff check agentguard/workbench tests
	$(RUN_PY) -m ruff format --check agentguard/workbench tests
	$(RUN_PY) -m mypy agentguard/workbench
	cd frontend && npm run lint

e2e:
	cd frontend && AGENTGUARD_PYTHON="$(abspath $(PY))" npm run test:e2e

e2e-webkit:
	cd frontend && AGENTGUARD_PYTHON="$(abspath $(PY))" PW_ENGINE=webkit npm run test:e2e

screenshots:
	cd frontend && AGENTGUARD_PYTHON="$(abspath $(PY))" npm run screenshots

eval:
	$(RUN_PY) -m agentguard workbench-eval --out "$(EVAL_DIR)"

verify: build test lint e2e
	@echo "Verification passed: backend tests, lint/types, frontend build, browser E2E."

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache frontend/dist frontend/test-results frontend/playwright-report frontend/.e2e-run
