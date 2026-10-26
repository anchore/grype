# override to use a locally built yardstick, e.g. make validate YARDSTICK=~/code/yardstick/bin/yardstick
YARDSTICK ?= ../../.tool/yardstick
GATES = gates/*.yaml

# update periodically with "make update-quality-gate-db" from the repo root
TEST_DB_URL_FILE = ./test-db
TEST_DB_URL = "$(shell cat $(TEST_DB_URL_FILE))"
TEST_DB = db.tar.zst

# formatting variables
BOLD := $(shell tput -T linux bold)
CYAN := $(shell tput -T linux setaf 6)
RESET := $(shell tput -T linux sgr0)

.PHONY: all
all: capture validate ## Fetch or capture all data and run all quality checks

.PHONY: validate
validate: tools ## Score the collected scans against the labels (exit 1 when a gate fails)
	$(YARDSTICK) score $(GATES)

.PHONY: capture
capture: tools grype $(TEST_DB) ## Get SBOMs for every image and scan them with grype from this checkout and the latest release
	$(YARDSTICK) collect scans $(GATES)

.PHONY: tools
tools: ## Install yardstick and the repo's other pinned tools (a no-op when they're current)
	$(MAKE) -C ../.. binny:install

.PHONY: grype
grype: ## Build the candidate grype from this checkout
	go build -o bin/grype ../../cmd/grype

$(TEST_DB):
	@curl -o $(TEST_DB) -SsL $(TEST_DB_URL)

.PHONY: clear-results
clear-results: ## Clear all yardstick scans
	rm -rf .yardstick

.PHONY: clean
clean: clear-results ## Clear all scans, the candidate grype and the DB
	rm -rf bin $(TEST_DB)

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
