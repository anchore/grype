BIN = grype
TEMPDIR = ./.tmp
RESULTSDIR = $(TEMPDIR)/results
COVER_REPORT = $(RESULTSDIR)/cover.report
COVER_TOTAL = $(RESULTSDIR)/cover.total
LICENSES_REPORT = $(RESULTSDIR)/licenses.json
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --timeout 5m --config .golangci.yaml
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)
# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 47
BOOTSTRAP_CACHE="c7afb99ad"

## Build variables
DISTDIR=./dist
SNAPSHOTDIR=./snapshot
GITTREESTATE=$(if $(shell git status --porcelain),dirty,clean)
SYFTVERSION=$(shell go list -m all | grep github.com/anchore/syft | awk '{print $$2}')
OS := $(shell uname)

ifeq ($(OS),Darwin)
	SNAPSHOT_CMD=$(shell realpath $(shell pwd)/$(SNAPSHOTDIR)/$(BIN)-macos_darwin_amd64/$(BIN))
else
	SNAPSHOT_CMD=$(shell realpath $(shell pwd)/$(SNAPSHOTDIR)/$(BIN)_linux_amd64/$(BIN))
endif

ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

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
test: unit validate-cyclonedx-schema integration acceptance-linux cli ## Run all tests (unit, integration, linux acceptance, and CLI tests)

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

.PHONY: ci-bootstrap
ci-bootstrap:
	DEBIAN_FRONTEND=noninteractive sudo apt update && sudo -E apt install -y bc jq libxml2-utils

.PHONY:
ci-bootstrap-mac:
	github_changelog_generator --version || sudo gem install github_changelog_generator

$(RESULTSDIR):
	mkdir -p $(RESULTSDIR)

$(TEMPDIR):
	mkdir -p $(TEMPDIR)

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMPDIR)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ v1.42.1
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMPDIR)/ v0.2.0
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMPDIR)/ v0.3.0
	.github/scripts/goreleaser-install.sh -b $(TEMPDIR)/ v0.177.0

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

.PHONY: bootstrap
bootstrap: $(RESULTSDIR) bootstrap-go bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)

.PHONY: static-analysis
static-analysis: lint check-go-mod-tidy check-licenses validate-grype-db-schema

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

check-go-mod-tidy:
	@ .github/scripts/go-mod-tidy-check.sh && echo "go.mod and go.sum are tidy!"

.PHONY: validate-cyclonedx-schema
validate-cyclonedx-schema:
	cd schema/cyclonedx && make

.PHONY: validate-grype-db-schema
validate-grype-db-schema:
	# ensure the codebase is only referencing a single grype-db schema version, multiple is not allowed
	python test/validate-grype-db-schema.py

.PHONY: lint-fix
lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(LINTCMD) --fix
	go mod tidy

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
	find test/integration/*.go test/integration/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum | tee test/integration/test-fixtures/cache.fingerprint

# note: this is used by CI to determine if the cli test fixture cache (docker image tars) should be busted
.PHONY: cli-fingerprint
cli-fingerprint:
	find test/cli/*.go test/cli/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum | tee test/cli/test-fixtures/cache.fingerprint

.PHONY: cli
cli: $(SNAPSHOTDIR) ## Run CLI tests
	chmod 755 "$(SNAPSHOT_CMD)"
	$(SNAPSHOT_CMD) version
	GRYPE_BINARY_LOCATION='$(SNAPSHOT_CMD)' \
		go test -count=1 -v ./test/cli

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
	# DOCKER_CLI_EXPERIMENTAL needed to support multi architecture builds for goreleaser
	# the release command protects us from image build regressions if QEMU fails or docker is changed
	BUILD_GIT_TREE_STATE=$(GITTREESTATE) \
	DOCKER_CLI_EXPERIMENTAL=enabled \
	SYFT_VERSION=$(SYFTVERSION) \
	$(TEMPDIR)/goreleaser release --skip-publish --skip-sign --rm-dist --snapshot --config $(TEMPDIR)/goreleaser.yaml

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

.PHONY: changelog
changelog: clean-changelog CHANGELOG.md
	@docker run -it --rm \
		-v $(shell pwd)/CHANGELOG.md:/CHANGELOG.md \
		rawkode/mdv \
			-t 748.5989 \
			/CHANGELOG.md

CHANGELOG.md:
	$(TEMPDIR)/chronicle -vv > CHANGELOG.md

.PHONY: validate-grype-test-config
validate-grype-test-config:
	# ensure the update URL is not overridden (not pointing to staging)
	@bash -c '\
		grep -q "update-url" test/grype-test-config.yaml; \
		if [ $$? -eq 0 ]; then \
			echo "Found \"update-url\" in CLI testing config. Cannot release if previous CLI testing did not use production (default) values"; \
		fi'

.PHONY: validate-syft-release-version
validate-syft-release-version:
	@./.github/scripts/syft-released-version-check.sh

.PHONY: release
release: clean-dist validate-grype-test-config CHANGELOG.md ## Build and publish final binaries and packages. Intended to be run only on macOS.
	$(call title,Publishing release artifacts)

	# Prepare for macOS-specific signing process
	.github/scripts/mac-prepare-for-signing.sh

	# login to docker
	# note: the previous step creates a new keychain, so it is important to reauth into docker.io
	@echo $${DOCKER_PASSWORD} | docker login docker.io -u $${DOCKER_USERNAME}  --password-stdin

	# create a config with the dist dir overridden
	echo "dist: $(DISTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	# release (note the version transformation from v0.7.0 --> 0.7.0)
	# DOCKER_CLI_EXPERIMENTAL needed to support multi architecture builds for goreleaser
	bash -c "\
		BUILD_GIT_TREE_STATE=$(GITTREESTATE) \
		DOCKER_CLI_EXPERIMENTAL=enabled \
		SYFT_VERSION=$(SYFTVERSION) \
		VERSION=$(VERSION:v%=%) \
		$(TEMPDIR)/goreleaser \
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
clean-dist: clean-changelog
	rm -rf $(DISTDIR) $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-changelog
clean-changelog:
	rm -f CHANGELOG.md
