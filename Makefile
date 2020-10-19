BIN = grype
TEMPDIR = ./.tmp
RESULTSDIR = $(TEMPDIR)/results
COVER_REPORT = $(RESULTSDIR)/cover.report
COVER_TOTAL = $(RESULTSDIR)/cover.total
LICENSES_REPORT = $(RESULTSDIR)/licenses.json
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --config .golangci.yaml
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)
# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 55

## Build variables
DISTDIR=./dist
SNAPSHOTDIR=./snapshot
GITTREESTATE=$(if $(shell git status --porcelain),dirty,clean)
SNAPSHOT_CMD=$(shell realpath $(shell pwd)/$(SNAPSHOTDIR)/grype_linux_amd64/grype)

ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

# used to generate the changelog from the second to last tag to the current tag (used in the release pipeline when the release tag is in place)
LAST_TAG := $(shell git describe --abbrev=0 --tags $(shell git rev-list --tags --max-count=1))
SECOND_TO_LAST_TAG := $(shell git describe --abbrev=0 --tags $(shell git rev-list --tags --skip=1 --max-count=1))

## Variable assertions

ifndef TEMPDIR
	$(error TEMPDIR is not set)
endif

ifndef RESULTSDIR
	$(error RESULTSDIR is not set)
endif

ifndef DISTDIR
	$(error DISTDIR is not set)
endif

ifndef SNAPSHOTDIR
	$(error SNAPSHOTDIR is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

.PHONY: all
all: clean static-analysis test ## Run all checks (linting, license check, unit, integration, and linux acceptance tests tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: test
test: unit validate-cyclonedx-schema integration acceptance-linux ## Run all tests (unit, integration, and linux acceptance tests )

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

ci-bootstrap: bootstrap
	DEBIAN_FRONTEND=noninteractive sudo apt update && sudo -E apt install -y bc jq libxml2-utils

.PHONY: boostrap
bootstrap: ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Boostrapping dependencies)
	@pwd
	# prep temp dirs
	mkdir -p $(TEMPDIR)
	mkdir -p $(RESULTSDIR)
	# install go dependencies
	go mod download
	# install utilities
	[ -f "$(TEMPDIR)/golangci" ] || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ v1.26.0
	[ -f "$(TEMPDIR)/bouncer" ] || curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMPDIR)/ v0.2.0
	[ -f "$(TEMPDIR)/goreleaser" ] || curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | sh -s -- -b $(TEMPDIR)/ v0.140.0

.PHONY: static-analysis
static-analysis: lint check-licenses validate-schema

.PHONY: lint
lint: ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINTCMD)

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: validate-schema
validate-schema:
	# ensure the codebase is only referencing a single grype-db schema version, multiple is not allowed
	python test/validate_schema.py

.PHONY: validate-cyclonedx-schema
validate-cyclonedx-schema:
	cd schema/cyclonedx && make
	
.PHONY: lint-fix
lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(LINTCMD) --fix

.PHONY: check-licenses
check-licenses:
	$(TEMPDIR)/bouncer check

.PHONY: unit
unit: ## Run unit tests (with coverage)
	$(call title,Running unit tests)
	mkdir -p $(RESULTSDIR)
	go test -coverprofile $(COVER_REPORT) $(shell go list ./... | grep -v anchore/grype/test)
	@go tool cover -func $(COVER_REPORT) | grep total |  awk '{print substr($$3, 1, length($$3)-1)}' > $(COVER_TOTAL)
	@echo "Coverage: $$(cat $(COVER_TOTAL))"
	@if [ $$(echo "$$(cat $(COVER_TOTAL)) >= $(COVERAGE_THRESHOLD)" | bc -l) -ne 1 ]; then echo "$(RED)$(BOLD)Failed coverage quality gate (> $(COVERAGE_THRESHOLD)%)$(RESET)" && false; fi

.PHONY: integration
integration: ## Run integration tests
	$(call title,Running integration tests)
	go test -v ./test/integration

# note: this is used by CI to determine if the integration test fixture cache (docker image tars) should be busted
.PHONY: integration-fingerprint
integration-fingerprint:
	find test/integration/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum | tee test/integration/test-fixtures/cache.fingerprint

.PHONY: clear-test-cache
clear-test-cache: ## Delete all test cache (built docker image tars)
	find . -type f -wholename "**/test-fixtures/cache/*.tar" -delete

.PHONY: build
build: $(SNAPSHOTDIR) ## Build release snapshot binaries and packages

$(SNAPSHOTDIR): ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)
	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	# build release snapshots
	BUILD_GIT_TREE_STATE=$(GITTREESTATE) \
	$(TEMPDIR)/goreleaser release --skip-publish --rm-dist --snapshot --config $(TEMPDIR)/goreleaser.yaml

.PHONY: acceptance-linux
acceptance-linux: $(SNAPSHOTDIR) ## Run acceptance tests on build snapshot binaries and packages (Linux)

# note: this is used by CI to determine if the inline-scan report cache should be busted for the inline-compare tests
.PHONY: compare-fingerprint
compare-fingerprint: ## Compare a snapshot build run of grype against inline-scan
	find test/inline-compare/* -type f -exec md5sum {} + | grep -v '\-reports' | grep -v 'fingerprint' | awk '{print $1}' | sort | md5sum | tee test/inline-compare/inline-compare.fingerprint

.PHONY: compare-snapshot
compare-snapshot: $(SNAPSHOTDIR)  ## Compare a main branch build run of grype against inline-scan
	chmod 755 $(SNAPSHOT_CMD)
	@cd test/inline-compare && GRYPE_CMD=$(SNAPSHOT_CMD) make

.PHONY: compare
compare:
	@cd test/inline-compare && make

.PHONY: changlog-release
changelog-release:
	@echo "Last tag: $(SECOND_TO_LAST_TAG)"
	@echo "Current tag: $(VERSION)"
	@docker run -i --rm  \
		-v "$(shell pwd)":/usr/local/src/your-app ferrarimarco/github-changelog-generator \
		--user anchore \
		--project $(BIN) \
		-t ${GITHUB_TOKEN} \
		--exclude-labels 'duplicate,question,invalid,wontfix,size:small,size:medium,size:large,size:x-large' \
		--no-pr-wo-labels \
		--no-issues-wo-labels \
		--since-tag $(SECOND_TO_LAST_TAG)

	@printf '\n$(BOLD)$(CYAN)Release $(VERSION) Changelog$(RESET)\n\n'
	@cat CHANGELOG.md

.PHONY: changelog-unreleased
changelog-unreleased: ## show the current changelog that will be produced on the next release (note: requires GITHUB_TOKEN set)
	@docker run -it --rm  \
		-v "$(shell pwd)":/usr/local/src/your-app ferrarimarco/github-changelog-generator \
		--user anchore \
		--project $(BIN) \
		-t ${GITHUB_TOKEN} \
		--exclude-labels 'duplicate,question,invalid,wontfix,size:small,size:medium,size:large,size:x-large' \
		--since-tag $(LAST_TAG)

	@printf '\n$(BOLD)$(CYAN)Unreleased Changes (closed PRs and issues will not be in the final changelog)$(RESET)\n'

	@docker run -it --rm \
		-v $(shell pwd)/CHANGELOG.md:/CHANGELOG.md \
		rawkode/mdv \
			-t 754.5889 \
			/CHANGELOG.md

.PHONY: release
release: clean-dist changelog-release ## Build and publish final binaries and packages
	$(call title,Publishing release artifacts)
	# create a config with the dist dir overridden
	echo "dist: $(DISTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	# release
	bash -c "BUILD_GIT_TREE_STATE=$(GITTREESTATE) $(TEMPDIR)/goreleaser \
		--rm-dist \
		--config $(TEMPDIR)/goreleaser.yaml \
		--release-notes <(cat CHANGELOG.md)"

	# verify checksum signatures
	.github/scripts/verify-signature.sh "$(DISTDIR)"

	# upload the version file that supports the application version update check (excluding pre-releases)
	.github/scripts/update-version-file.sh "$(DISTDIR)" "$(VERSION)"

.PHONY: clean
clean: clean-dist clean-snapshot  ## Remove previous builds and result reports
	rm -rf $(RESULTSDIR)/*

.PHONY: clean-snapshot
clean-snapshot:
	rm -rf $(SNAPSHOTDIR) $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-dist
clean-dist:
	rm -rf $(DISTDIR) $(TEMPDIR)/goreleaser.yaml
