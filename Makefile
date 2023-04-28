BIN := grype
TEMP_DIR := ./.tmp

# Command templates #################################
LINT_CMD := $(TEMP_DIR)/golangci-lint run --tests=false
GOIMPORTS_CMD := $(TEMP_DIR)/gosimports -local github.com/anchore
RELEASE_CMD := $(TEMP_DIR)/goreleaser release --clean
SNAPSHOT_CMD := $(RELEASE_CMD) --skip-publish --skip-sign --snapshot
CHRONICLE_CMD = $(TEMP_DIR)/chronicle
GLOW_CMD = $(TEMP_DIR)/glow

# Tool versions #################################
GOLANGCILINT_VERSION := v1.52.2
GOSIMPORTS_VERSION := v0.3.8
BOUNCER_VERSION := v0.4.0
CHRONICLE_VERSION := v0.6.0
GORELEASER_VERSION := v1.17.2
YAJSV_VERSION := v1.4.1
QUILL_VERSION := v0.2.0
GLOW_VERSION := v1.5.0
SKOPEO_VERSION := v1.12.0

# Formatting variables ############################
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

# Test variables #################################
# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 47
RESULTS_DIR := $(TEMP_DIR)/results
COVER_REPORT := $(RESULTS_DIR)/cover.report
COVER_TOTAL := $(RESULTS_DIR)/cover.total
LICENSES_REPORT := $(RESULTS_DIR)/licenses.json

## Build variables #################################
VERSION := $(shell git describe --dirty --always --tags)
DIST_DIR := ./dist
SNAPSHOT_DIR := ./snapshot
CHANGELOG := CHANGELOG.md
OS := $(shell uname | tr '[:upper:]' '[:lower:]')
SNAPSHOT_BIN := $(realpath $(shell pwd)/$(SNAPSHOT_DIR)/$(OS)-build_$(OS)_amd64_v1/$(BIN))

ifndef TEMP_DIR
	$(error TEMP_DIR is not set)
endif

ifndef RESULTS_DIR
	$(error RESULTS_DIR is not set)
endif

ifndef DIST_DIR
	$(error DIST_DIR is not set)
endif

ifndef SNAPSHOT_DIR
	$(error SNAPSHOT_DIR is not set)
endif

ifndef VERSION
	$(error VERSION is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

define safe_rm_rf
	bash -c 'test -z "$(1)" && false || rm -rf $(1)'
endef

define safe_rm_rf_children
	bash -c 'test -z "$(1)" && false || rm -rf $(1)/*'
endef

.DEFAULT_GOAL:=help

.PHONY: all
all: static-analysis test ## Run all checks (linting, license check, unit, integration, and linux acceptance tests tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: static-analysis
static-analysis: check-go-mod-tidy lint check-licenses validate-grype-db-schema

.PHONY: test
test: unit integration validate-cyclonedx-schema validate-grype-db-schema cli ## Run all tests (unit, integration, linux acceptance, and CLI tests)

.PHONY: validate-cyclonedx-schema
validate-cyclonedx-schema:
	cd schema/cyclonedx && make

.PHONY: validate-grype-db-schema
validate-grype-db-schema:
	# ensure the codebase is only referencing a single grype-db schema version, multiple is not allowed
	python test/validate-grype-db-schema.py


## Bootstrapping targets #################################

.PHONY: bootstrap
bootstrap: $(TEMP_DIR) bootstrap-go bootstrap-tools ## Download and install all tooling dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMP_DIR)
	curl -sSfL https://raw.githubusercontent.com/anchore/quill/main/install.sh | sh -s -- -b $(TEMP_DIR)/ $(QUILL_VERSION)
	GO111MODULE=off GOBIN=$(realpath $(TEMP_DIR)) go get -u golang.org/x/perf/cmd/benchstat
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMP_DIR)/ $(GOLANGCILINT_VERSION)
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMP_DIR)/ $(BOUNCER_VERSION)
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMP_DIR)/ $(CHRONICLE_VERSION)
	.github/scripts/goreleaser-install.sh -d -b $(TEMP_DIR)/ $(GORELEASER_VERSION)
	# the only difference between goimports and gosimports is that gosimports removes extra whitespace between import blocks (see https://github.com/golang/go/issues/20818)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/rinchsan/gosimports/cmd/gosimports@$(GOSIMPORTS_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/neilpa/yajsv@$(YAJSV_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/charmbracelet/glow@$(GLOW_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" CGO_ENABLED=0 GO_DYN_FLAGS="" go install -tags "containers_image_openpgp" github.com/containers/skopeo/cmd/skopeo@$(SKOPEO_VERSION)

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

$(TEMP_DIR):
	mkdir -p $(TEMP_DIR)


## Static analysis targets #################################

.PHONY: lint
lint:  ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINT_CMD)
	@[ -z "$(shell $(GOIMPORTS_CMD) -d .)" ] || (echo "goimports needs to be fixed" && false)

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: format
format: ## Auto-format all source code
	$(call title,Running formatters)
	gofmt -w -s .
	$(GOIMPORTS_CMD) -w .
	go mod tidy

.PHONY: lint-fix
lint-fix: format  ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	$(LINT_CMD) --fix

.PHONY: check-licenses
check-licenses:  ## Ensure transitive dependencies are compliant with the current license policy
	$(call title,Checking for license compliance)
	$(TEMP_DIR)/bouncer check ./...

check-go-mod-tidy:
	@ .github/scripts/go-mod-tidy-check.sh && echo "go.mod and go.sum are tidy!"

## Testing targets #################################

.PHONY: unit
unit: $(TEMP_DIR) ## Run unit tests (with coverage)
	$(call title,Running unit tests)
	go test -coverprofile $(TEMP_DIR)/unit-coverage-details.txt $(shell go list ./... | grep -v anchore/grype/test)
	@.github/scripts/coverage.py $(COVERAGE_THRESHOLD) $(TEMP_DIR)/unit-coverage-details.txt

.PHONY: integration
integration:  ## Run integration tests
	$(call title,Running integration tests)
	go test -v ./test/integration

.PHONY: quality
quality: ## Run quality tests
	$(call title,Running quality tests)
	cd test/quality && make

.PHONY: cli
cli: $(SNAPSHOT_DIR)  ## Run CLI tests
	chmod 755 "$(SNAPSHOT_BIN)"
	$(SNAPSHOT_BIN) version
	SYFT_BINARY_LOCATION='$(SNAPSHOT_BIN)' \
		go test -count=1 -timeout=15m -v ./test/cli

## Test-fixture-related targets #################################

# note: this is used by CI to determine if various test fixture cache should be restored or recreated
# TODO (cphillips) check for all fixtures and individual makefile
fingerprints:
	$(call title,Creating all test cache input fingerprints)

	# for IMAGE integration test fixtures
	cd test/integration/test-fixtures && \
		make cache.fingerprint

	# for INSTALL integration test fixtures
	cd test/install && \
		make cache.fingerprint

	# for CLI test fixtures
	cd test/cli/test-fixtures && \
		make cache.fingerprint

.PHONY: show-test-image-cache
show-test-image-cache:  ## Show all docker and image tar cache
	$(call title,Docker daemon cache)
	@docker images --format '{{.ID}} {{.Repository}}:{{.Tag}}' | grep stereoscope-fixture- | sort

	$(call title,Tar cache)
	@find . -type f -wholename "**/test-fixtures/cache/stereoscope-fixture-*.tar" | sort

.PHONY: show-test-snapshots
show-test-snapshots:  ## Show all test snapshots
	$(call title,Test snapshots)
	@find . -type f -wholename "**/test-fixtures/snapshot/*" | sort

## install.sh testing targets #################################

install-test: $(SNAPSHOT_DIR)
	cd test/install && \
		make

install-test-cache-save: $(SNAPSHOT_DIR)
	cd test/install && \
		make save

install-test-cache-load: $(SNAPSHOT_DIR)
	cd test/install && \
		make load

install-test-ci-mac: $(SNAPSHOT_DIR)
	cd test/install && \
		make ci-test-mac

.PHONY: compare-test-deb-package-install
compare-test-deb-package-install: $(TEMP_DIR) $(SNAPSHOT_DIR)
	$(call title,Running compare test: DEB install)
	$(COMPARE_DIR)/deb.sh \
			$(SNAPSHOT_DIR) \
			$(COMPARE_DIR) \
			$(COMPARE_TEST_IMAGE) \
			$(TEMP_DIR)

.PHONY: compare-test-rpm-package-install
compare-test-rpm-package-install: $(TEMP_DIR) $(SNAPSHOT_DIR)
	$(call title,Running compare test: RPM install)
	$(COMPARE_DIR)/rpm.sh \
			$(SNAPSHOT_DIR) \
			$(COMPARE_DIR) \
			$(COMPARE_TEST_IMAGE) \
			$(TEMP_DIR)

## Code generation targets #################################
## TODO (cphillips) what does grype have here?

## Build-related targets #################################

.PHONY: build
build: $(SNAPSHOT_DIR)

$(SNAPSHOT_DIR):  ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOT_DIR)" > $(TEMP_DIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMP_DIR)/goreleaser.yaml

	# build release snapshots
		$(SNAPSHOT_CMD) --config $(TEMP_DIR)/goreleaser.yaml

.PHONY: changelog
changelog: clean-changelog  ## Generate and show the changelog for the current unreleased version
	$(CHRONICLE_CMD) -vv -n --version-file VERSION > $(CHANGELOG)
	@$(GLOW_CMD) $(CHANGELOG)

$(CHANGELOG):
	$(CHRONICLE_CMD) -vvv > $(CHANGELOG)

.PHONY: release
release:
	@.github/scripts/trigger-release.sh

.PHONY: ci-release
ci-release: ci-check clean-dist $(CHANGELOG)
	$(call title,Publishing release artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(DIST_DIR)" > $(TEMP_DIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMP_DIR)/goreleaser.yaml

	bash -c "\
		$(RELEASE_CMD) \
			--config $(TEMP_DIR)/goreleaser.yaml \
			--release-notes <(cat $(CHANGELOG)) \
				 || (cat /tmp/quill-*.log && false)"

	# upload the version file that supports the application version update check (excluding pre-releases)
	.github/scripts/update-version-file.sh "$(DIST_DIR)" "$(VERSION)"

.PHONY: ci-check
ci-check:
	@.github/scripts/ci-check.sh

## Cleanup targets #################################

.PHONY: clean
clean: clean-dist clean-snapshot ## Remove previous builds, result reports, and test cache
	$(call safe_rm_rf_children,$(TEMP_DIR))

.PHONY: clean-snapshot
clean-snapshot:
	$(call safe_rm_rf,$(SNAPSHOT_DIR))
	rm -f $(TEMP_DIR)/goreleaser.yaml

.PHONY: clean-dist
clean-dist: clean-changelog
	$(call safe_rm_rf,$(DIST_DIR))
	rm -f $(TEMP_DIR)/goreleaser.yaml

.PHONY: clean-changelog
clean-changelog:
	rm -f $(CHANGELOG) VERSION

clean-test-image-cache: clean-test-image-tar-cache clean-test-image-docker-cache ## Clean test image cache

## Halp! #################################

.PHONY: help
help:  ## Display this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'


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

.PHONY: clean-test-cache
clean-test-cache: ## Delete all test cache (built docker image tars)
	find . -type f -wholename "**/test-fixtures/cache/*.tar" -delete
