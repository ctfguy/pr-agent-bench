UV ?= uv
RUN ?= $(UV) run
RESULTS_DIR ?= results

ADVISORY ?= GHSA-jpx3-25r2-jq5g
URL ?=
LIMIT ?=
SEVERITY ?= critical
PUBLISHED_SINCE ?=
PUBLISHED_UNTIL ?=
UPDATED_SINCE ?=
UPDATED_UNTIL ?=

WORKERS ?= 1
AGENT_COST_CAP_USD ?=
SKIP_GIT ?= 0
NO_MODEL ?= 0
NO_RAW ?= 1
NO_ENRICH ?= 0
ALLOW_UNAUTHENTICATED ?= 0

OUTPUT_NAME = $(if $(URL),url,$(if $(ADVISORY),$(ADVISORY),latest))
COLLECT_OUTPUT ?= $(RESULTS_DIR)/$(OUTPUT_NAME)_collected.json
ANALYZE_OUTPUT ?= $(RESULTS_DIR)/$(OUTPUT_NAME)_analyzed.json
EVAL_REPORT ?= $(RESULTS_DIR)/$(OUTPUT_NAME)_eval.json

LABELS ?= test_dataset/labels.json
ANALYSIS ?= $(ANALYZE_OUTPUT)

REPO ?=
DOCKERIZE_REPO_LOCAL ?= 0
DOCKERIZE_FORCE ?= 0
DOCKERIZE_SKIP_RUNTIME ?= 0
DOCKERIZE_MAX_RETRIES ?= 3
DOCKERIZE_OUTPUT ?= $(RESULTS_DIR)/dockerize_$(subst /,_,$(REPO)).json
INFRA_COMPOSE ?= docker-compose.infra.yml
TEMPORAL_ADDRESS ?= localhost:7233
TEMPORAL_NAMESPACE ?= default
TEMPORAL_TASK_QUEUE ?= advisory-miner
DASHBOARD_HOST ?= 127.0.0.1
DASHBOARD_PORT ?= 8765

.PHONY: help collect analyze eval dockerize dashboard infra-config infra-up infra-down infra-logs temporal-worker temporal-submit prod-run test

help:
	@printf '%s\n' \
	  'Targets:' \
	  '  make collect    Collect advisory data only' \
	  '  make analyze    Collect and analyze advisory data' \
	  '  make eval       Compare an analysis output to ground-truth labels' \
	  '  make dockerize  Generate or validate Docker setup for a repo (Bonus 2)' \
	  '  make dashboard  Run local web dashboard' \
	  '  make infra-up   Start local Temporal + Langfuse stack' \
	  '  make infra-down Stop local Temporal + Langfuse stack' \
	  '  make temporal-worker  Run Temporal worker' \
	  '  make temporal-submit  Submit collection + analysis workflow to Temporal' \
	  '  make prod-run  Build and run full Dockerized Temporal/Langfuse analyzer stack' \
	  '  make test       Run tests' \
	  '' \
	  'Examples:' \
	  '  make analyze' \
	  '  make analyze ADVISORY=GHSA-jpx3-25r2-jq5g' \
	  '  make analyze URL=https://github.com/advisories/GHSA-jpx3-25r2-jq5g' \
	  '  make analyze ADVISORY= LIMIT=5 SEVERITY=critical WORKERS=5' \
	  '  make analyze SKIP_GIT=1 NO_MODEL=1' \
	  '  make eval LABELS=test_dataset/labels.json ANALYSIS=results/latest_analyzed.json' \
	  '  make dockerize REPO=harttle/liquidjs' \
	  '  make dockerize REPO=. DOCKERIZE_REPO_LOCAL=1 DOCKERIZE_SKIP_RUNTIME=1' \
	  '  make dashboard' \
	  '  make infra-up && make temporal-worker' \
	  '  make temporal-submit ADVISORY= LIMIT=20 NO_ENRICH=1' \
	  '  make prod-run ADVISORY=GHSA-5c25-7vpj-9mqh'

collect:
	@mkdir -p '$(RESULTS_DIR)'
	@set -eu; \
	set -a; [ ! -f .env ] || . ./.env; set +a; \
	set --; \
	if [ -n '$(URL)' ]; then \
	  set -- "$$@" --url '$(URL)'; \
	elif [ -n '$(ADVISORY)' ]; then \
	  set -- "$$@" --advisory '$(ADVISORY)'; \
	else \
	  set -- "$$@" --severity '$(SEVERITY)'; \
	  if [ -n '$(LIMIT)' ]; then set -- "$$@" --limit '$(LIMIT)'; fi; \
	fi; \
	if [ -n '$(PUBLISHED_SINCE)' ]; then set -- "$$@" --published-since '$(PUBLISHED_SINCE)'; fi; \
	if [ -n '$(PUBLISHED_UNTIL)' ]; then set -- "$$@" --published-until '$(PUBLISHED_UNTIL)'; fi; \
	if [ -n '$(UPDATED_SINCE)' ]; then set -- "$$@" --updated-since '$(UPDATED_SINCE)'; fi; \
	if [ -n '$(UPDATED_UNTIL)' ]; then set -- "$$@" --updated-until '$(UPDATED_UNTIL)'; fi; \
	if [ '$(NO_RAW)' = '1' ]; then set -- "$$@" --no-raw; fi; \
	if [ '$(NO_ENRICH)' = '1' ]; then set -- "$$@" --no-enrich; fi; \
	if [ '$(ALLOW_UNAUTHENTICATED)' = '1' ]; then set -- "$$@" --allow-unauthenticated; fi; \
	$(RUN) advisory-miner "$$@" --output '$(COLLECT_OUTPUT)'
	@printf 'Collector output: %s\n' '$(COLLECT_OUTPUT)'

analyze: collect
	@set -eu; \
	set -a; [ ! -f .env ] || . ./.env; set +a; \
	set -- --input '$(COLLECT_OUTPUT)' --output '$(ANALYZE_OUTPUT)' --workers '$(WORKERS)'; \
	if [ -n '$(AGENT_COST_CAP_USD)' ]; then set -- "$$@" --cost-cap-usd '$(AGENT_COST_CAP_USD)'; fi; \
	if [ '$(SKIP_GIT)' = '1' ]; then set -- "$$@" --skip-git; fi; \
	if [ '$(NO_MODEL)' = '1' ]; then set -- "$$@" --no-model; fi; \
	if [ '$(ALLOW_UNAUTHENTICATED)' = '1' ]; then set -- "$$@" --allow-unauthenticated; fi; \
	$(RUN) advisory-miner analyze "$$@"
	@printf 'Analysis output: %s\n' '$(ANALYZE_OUTPUT)'

eval:
	@set -eu; \
	set -a; [ ! -f .env ] || . ./.env; set +a; \
	$(RUN) advisory-miner eval \
	  --labels '$(LABELS)' --analysis '$(ANALYSIS)' --report '$(EVAL_REPORT)'

dockerize:
	@set -eu; \
	if [ -z '$(REPO)' ]; then echo 'usage: make dockerize REPO=owner/repo'; exit 2; fi; \
	mkdir -p '$(RESULTS_DIR)'; \
	set -a; [ ! -f .env ] || . ./.env; set +a; \
	set -- --repo '$(REPO)' --max-retries '$(DOCKERIZE_MAX_RETRIES)' --output '$(DOCKERIZE_OUTPUT)'; \
	if [ '$(DOCKERIZE_REPO_LOCAL)' = '1' ]; then set -- "$$@" --local; fi; \
	if [ '$(DOCKERIZE_FORCE)' = '1' ]; then set -- "$$@" --force; fi; \
	if [ '$(DOCKERIZE_SKIP_RUNTIME)' = '1' ]; then set -- "$$@" --skip-runtime; fi; \
	$(RUN) advisory-miner dockerize "$$@"

dashboard:
	@set -a; [ ! -f .env ] || . ./.env; set +a; \
	$(RUN) advisory-miner dashboard --host '$(DASHBOARD_HOST)' --port '$(DASHBOARD_PORT)' --results-dir '$(RESULTS_DIR)' --cache-root '.cache'

infra-config:
	@docker compose -f '$(INFRA_COMPOSE)' config >/dev/null
	@printf 'infra compose config ok\n'

infra-up:
	@docker compose -f '$(INFRA_COMPOSE)' up -d
	@printf 'Temporal UI: http://localhost:8088\nLangfuse UI: http://localhost:3100\n'

infra-down:
	@docker compose -f '$(INFRA_COMPOSE)' down

infra-logs:
	@docker compose -f '$(INFRA_COMPOSE)' logs -f --tail=100

temporal-worker:
	@set -a; [ ! -f .env ] || . ./.env; set +a; \
	$(RUN) advisory-miner temporal-worker --address '$(TEMPORAL_ADDRESS)' --namespace '$(TEMPORAL_NAMESPACE)' --task-queue '$(TEMPORAL_TASK_QUEUE)'

temporal-submit:
	@set -eu; \
	set -a; [ ! -f .env ] || . ./.env; set +a; \
	set -- --address '$(TEMPORAL_ADDRESS)' --namespace '$(TEMPORAL_NAMESPACE)' --task-queue '$(TEMPORAL_TASK_QUEUE)'; \
	if [ -n '$(URL)' ]; then \
	  set -- "$$@" --url '$(URL)'; \
	elif [ -n '$(ADVISORY)' ]; then \
	  set -- "$$@" --advisory '$(ADVISORY)'; \
	else \
	  set -- "$$@" --severity '$(SEVERITY)'; \
	  if [ -n '$(LIMIT)' ]; then set -- "$$@" --limit '$(LIMIT)'; fi; \
	fi; \
	if [ -n '$(PUBLISHED_SINCE)' ]; then set -- "$$@" --published-since '$(PUBLISHED_SINCE)'; fi; \
	if [ -n '$(PUBLISHED_UNTIL)' ]; then set -- "$$@" --published-until '$(PUBLISHED_UNTIL)'; fi; \
	if [ -n '$(UPDATED_SINCE)' ]; then set -- "$$@" --updated-since '$(UPDATED_SINCE)'; fi; \
	if [ -n '$(UPDATED_UNTIL)' ]; then set -- "$$@" --updated-until '$(UPDATED_UNTIL)'; fi; \
	if [ '$(NO_RAW)' = '1' ]; then set -- "$$@" --no-raw; fi; \
	if [ '$(NO_ENRICH)' = '1' ]; then set -- "$$@" --no-enrich; fi; \
	if [ '$(SKIP_GIT)' = '1' ]; then set -- "$$@" --skip-git; fi; \
	if [ '$(ALLOW_UNAUTHENTICATED)' = '1' ]; then set -- "$$@" --allow-unauthenticated; fi; \
	$(RUN) advisory-miner temporal-submit "$$@"

prod-run:
	@set -eu; \
	set -a; [ ! -f .env ] || . ./.env; set +a; \
	docker compose -f '$(INFRA_COMPOSE)' build advisory-worker; \
	docker compose -f '$(INFRA_COMPOSE)' up -d advisory-temporal-ui advisory-langfuse-web advisory-langfuse-worker advisory-worker; \
	docker compose -f '$(INFRA_COMPOSE)' run --rm \
	  -e ADVISORY='$(ADVISORY)' \
	  -e URL='$(URL)' \
	  -e LIMIT='$(LIMIT)' \
	  -e SEVERITY='$(SEVERITY)' \
	  advisory-submit; \
	printf 'Temporal UI: %s\nLangfuse UI: %s\nResults: %s\n' 'http://localhost:8088' 'http://localhost:3100' '$(RESULTS_DIR)'

test:
	@$(RUN) python -m compileall -q src tests
	@$(RUN) python -m unittest discover -s tests
