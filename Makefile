# Arbitr developer commands. CI runs locally, not on hosted runners.
SHELL := bash
.DEFAULT_GOAL := help
.PHONY: help setup ci ci-fast ci-docker act sim formal formal-large load soak release-check clean

help: ## Show this help
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | sort

setup: ## Install dependencies and git hooks
	uv sync --locked --all-extras
	bash scripts/install-hooks.sh

ci: ## Full local CI pipeline (required before every commit and push)
	bash scripts/ci.sh

ci-fast: ## Lint, format, types, writing rule and unit tests (under 60 s)
	bash scripts/ci.sh --fast

ci-docker: ## Full CI inside the pinned Linux image (deploy/Dockerfile.ci)
	bash scripts/ci_docker.sh

act: ## Run .github/workflows/ci.yml locally with act, log kept in ci-logs/
	@mkdir -p ci-logs; set -o pipefail; \
	log="ci-logs/$$(date -u +%Y%m%dT%H%M%SZ)-$$(git rev-parse --short=12 HEAD)-act.log"; \
	bash scripts/with_env.sh act workflow_dispatch -W .github/workflows/ci.yml 2>&1 | tee "$$log"; \
	rc=$${PIPESTATUS[0]}; echo "act exit code $$rc, log $$log" | tee -a "$$log"; exit $$rc

sim: ## Replay one simulation seed: make sim SEED=123
	@test -n "$(SEED)" || (echo "usage: make sim SEED=<seed>" >&2; exit 1)
	uv run --locked python tests/simulation/run.py --seed $(SEED) --verbose

formal: ## TLC on the small models
	bash scripts/with_env.sh bash scripts/tlc.sh small

formal-large: ## TLC on the large models
	bash scripts/with_env.sh bash scripts/tlc.sh large

load: ## Load test at 2x the throughput target (not built yet)
	@echo "make load: not built yet." >&2; exit 1

soak: ## One hour soak test (not built yet)
	@echo "make soak: not built yet." >&2; exit 1

release-check: ## Everything required before a release
	ARBITR_SIM_SEEDS=200000 ARBITR_TLC_MODEL=large bash scripts/ci_docker.sh
	$(MAKE) soak
	bash scripts/upgrade_test.sh
	@echo "mutation testing and the image scan are not built yet" >&2; exit 1

clean: ## Remove build and tool caches (keeps ci-logs)
	rm -rf dist build .tools/site .tools/pkg-venv .tools/tlc-states .mypy_cache .ruff_cache .pytest_cache .hypothesis
