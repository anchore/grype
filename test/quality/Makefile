SBOM_STORE_TAG = md5-$(shell md5sum .yardstick.yaml | cut -d' ' -f1)
SBOM_STORE_IMAGE = ghcr.io/anchore/grype/quality-test-sbom-store:$(SBOM_STORE_TAG)
ACTIVATE_VENV = . venv/bin/activate &&
YARDSTICK = $(ACTIVATE_VENV) yardstick -v
YARDSTICK_RESULT_DIR = .yardstick/result
YARDSTICK_LABELS_DIR = .yardstick/labels
VULNERABILITY_LABELS = ./vulnerability-labels
RESULT_SET = pr_vs_latest_via_sbom

# update periodically with values from "grype db list"
TEST_DB_URL_FILE = ./test-db-url
TEST_DB_URL = $(shell cat $(TEST_DB_URL_FILE))
TEST_DB = db.tar.gz

# formatting variables
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

.PHONY: all
all: capture validate ## Fetch or capture all data and run all quality checks

.PHONY: validate
validate: venv $(VULNERABILITY_LABELS)/Makefile ## Run all quality checks against already collected data
	$(YARDSTICK) validate -r $(RESULT_SET) -r $(RESULT_SET)_2022

.PHONY: capture
capture: sboms vulns ## Collect and store all syft and grype results

.PHONY: vulns
vulns: venv $(TEST_DB) ## Collect and store all grype results
	$(YARDSTICK) -v result capture -r $(RESULT_SET)
	$(YARDSTICK) -v result capture -r $(RESULT_SET)_2022

$(TEST_DB):
	@curl -o $(TEST_DB) -SsL $(TEST_DB_URL)

.PHONY: sboms
sboms: $(YARDSTICK_RESULT_DIR) venv clear-results ## Collect and store all syft results (deletes all existing results)
	bash -c "make download-sboms || ($(YARDSTICK) -v result capture -r $(RESULT_SET) --only-producers && $(YARDSTICK) -v result capture -r $(RESULT_SET)_2022 --only-producers)"

.PHONY: download-sboms
download-sboms: $(VULNERABILITY_LABELS)/Makefile
	cd vulnerability-match-labels && make venv
	bash -c "export ORAS_CACHE=$(shell pwd)/.oras-cache && make venv && . vulnerability-match-labels/venv/bin/activate && ./vulnerability-match-labels/sboms.py download -r $(RESULT_SET) && ./vulnerability-match-labels/sboms.py download -r $(RESULT_SET)_2022"

venv: venv/touchfile

venv/touchfile: requirements.txt
	test -d venv || python3 -m venv venv
	$(ACTIVATE_VENV) pip install -Ur requirements.txt
	touch venv/touchfile

$(YARDSTICK_RESULT_DIR):
	mkdir -p $(YARDSTICK_RESULT_DIR)

$(VULNERABILITY_LABELS)/Makefile:
	git submodule update vulnerability-match-labels

.PHONY: clear-results
clear-results: venv ## Clear all existing yardstick results
	$(YARDSTICK) result clear

.PHONY: clean
clean: clear-results ## Clear all existing yardstick results and delete python environment
	rm -rf venv
	find -iname "*.pyc" -delete

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

