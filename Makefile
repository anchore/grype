BIN = grype
TEMPDIR = ./.tmp
RESULTSDIR = $(TEMPDIR)/results
COVER_REPORT = $(RESULTSDIR)/cover.report
COVER_TOTAL = $(RESULTSDIR)/cover.total
LICENSES_REPORT = $(RESULTSDIR)/licenses.json
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --timeout 5m --config .golangci.yaml
GOIMPORTS_CMD = $(TEMPDIR)/gosimports -local github.com/anchore
RELEASE_CMD=$(TEMPDIR)/goreleaser release --rm-dist
SNAPSHOT_CMD=$(RELEASE_CMD) --skip-publish --snapshot
VERSION=$(shell git describe --dirty --always --tags)

# formatting variables
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

# CI cache busting values; change these if you want CI to not use previous stored cache
BOOTSTRAP_CACHE="c7afb99ad"
INTEGRATION_CACHE_BUSTER="894d8ca"

## Build variables
DISTDIR=./dist
SNAPSHOTDIR=./snapshot
OS=$(shell uname | tr '[:upper:]' '[:lower:]')
SYFT_VERSION=$(shell go list -m all | grep github.com/anchore/syft | awk '{print $$2}')
SNAPSHOT_BIN=$(shell realpath $(shell pwd)/$(SNAPSHOTDIR)/$(OS)-build_$(OS)_amd64/$(BIN))


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

.PHONY: all
all: clean static-analysis test ## Run all checks (linting, license check, unit, integration, and linux acceptance tests tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: test
test: unit validate-cyclonedx-schema integration cli ## Run all tests (unit, integration, linux acceptance, and CLI tests)

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

.PHONY: ci-bootstrap
ci-bootstrap:
	DEBIAN_FRONTEND=noninteractive sudo apt update && sudo -E apt install -y bc jq libxml2-utils

$(RESULTSDIR):
	mkdir -p $(RESULTSDIR)

$(TEMPDIR):
	mkdir -p $(TEMPDIR)

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMPDIR)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ v1.45.0
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMPDIR)/ v0.3.0
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMPDIR)/ v0.3.0
	# the only difference between goimports and gosimports is that gosimports removes extra whitespace between import blocks (see https://github.com/golang/go/issues/20818)
	GOBIN="$(shell realpath $(TEMPDIR))" go install github.com/rinchsan/gosimports/cmd/gosimports@v0.1.5
	.github/scripts/goreleaser-install.sh -b $(TEMPDIR)/ v1.4.1

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

.PHONY: bootstrap
bootstrap: $(RESULTSDIR) bootstrap-go bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)

.PHONY: static-analysis
static-analysis: check-go-mod-tidy check-licenses validate-grype-db-schema

.PHONY: lint
lint: ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINTCMD)
	@[ -z "$(shell $(GOIMPORTS_CMD) -d .)" ] || (echo "goimports needs to be fixed" && false)

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: lint-fix
lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(GOIMPORTS_CMD) -w .
	$(LINTCMD) --fix
	go mod tidy

.PHONY: check-licenses
check-licenses:
	$(TEMPDIR)/bouncer check

check-go-mod-tidy:
	@ .github/scripts/go-mod-tidy-check.sh && echo "go.mod and go.sum are tidy!"

.PHONY: validate-cyclonedx-schema
validate-cyclonedx-schema:
	cd schema/cyclonedx && make

.PHONY: validate-grype-db-schema
validate-grype-db-schema:
	# ensure the codebase is only referencing a single grype-db schema version, multiple is not allowed
	python test/validate-grype-db-schema.py

.PHONY: unit
unit: ## Run unit tests (with coverage)
	$(call title,Running unit tests)
	mkdir -p $(RESULTSDIR)
	go test -coverprofile $(COVER_REPORT) $(shell go list ./... | grep -v anchore/grype/test)
	@go tool cover -func $(COVER_REPORT) | grep total |  awk '{print substr($$3, 1, length($$3)-1)}' > $(COVER_TOTAL)
	@echo "Coverage: $$(cat $(COVER_TOTAL))"
	@if [ $$(echo "$$(cat $(COVER_TOTAL)) >= $(COVERAGE_THRESHOLD)" | bc -l) -ne 1 ]; then echo "$(RED)$(BOLD)Failed coverage quality gate (> $(COVERAGE_THRESHOLD)%)$(RESET)" && false; fi

# note: this is used by CI to determine if the install test fixture cache (docker image tars) should be busted
install-fingerprint:
	cd test/install && \
		make cache.fingerprint

install-test: $(SNAPSHOTDIR)
	cd test/install && \
		make

install-test-cache-save: $(SNAPSHOTDIR)
	cd test/install && \
		make save

install-test-cache-load: $(SNAPSHOTDIR)
	cd test/install && \
		make load

install-test-ci-mac: $(SNAPSHOTDIR)
	cd test/install && \
		make ci-test-mac

.PHONY: integration
integration: ## Run integration tests
	$(call title,Running integration tests)
	go test -v ./test/integration

# note: this is used by CI to determine if the integration test fixture cache (docker image tars) should be busted
.PHONY: integration-fingerprint
integration-fingerprint:
	find test/integration/*.go test/integration/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | tee /dev/stderr | md5sum | tee test/integration/test-fixtures/cache.fingerprint && echo "$(INTEGRATION_CACHE_BUSTER)" >> test/integration/test-fixtures/cache.fingerprint

# note: this is used by CI to determine if the cli test fixture cache (docker image tars) should be busted
.PHONY: cli-fingerprint
cli-fingerprint:
	find test/cli/*.go test/cli/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum | tee test/cli/test-fixtures/cache.fingerprint

.PHONY: cli
cli: $(SNAPSHOTDIR) ## Run CLI tests
	chmod 755 "$(SNAPSHOT_BIN)"
	GRYPE_BINARY_LOCATION='$(SNAPSHOT_BIN)' \
		go test -count=1 -v ./test/cli

.PHONY: build
build: $(SNAPSHOTDIR) ## Build release snapshot binaries and packages

$(SNAPSHOTDIR): ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	# build release snapshots
	bash -c "\
		SKIP_SIGNING=true \
		SYFT_VERSION=$(SYFT_VERSION)\
			$(SNAPSHOT_CMD) --skip-sign --config $(TEMPDIR)/goreleaser.yaml"

.PHONY: snapshot-with-signing
snapshot-with-signing: ## Build snapshot release binaries and packages (with dummy signing)
	$(call title,Building snapshot artifacts (+ signing))

	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	rm -f .github/scripts/apple-signing/log/*.txt

	# build release snapshots
	bash -c "\
		SYFT_VERSION=$(SYFT_VERSION)\
			$(SNAPSHOT_CMD) --config $(TEMPDIR)/goreleaser.yaml || (cat .github/scripts/apple-signing/log/*.txt && false)"

	# remove the keychain with the trusted self-signed cert automatically
	.github/scripts/apple-signing/cleanup.sh

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
release: clean-dist CHANGELOG.md  ## Build and publish final binaries and packages. Intended to be run only on macOS.
	$(call title,Publishing release artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(DISTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	rm -f .github/scripts/apple-signing/log/*.txt

	# note: notarization cannot be done in parallel, thus --parallelism 1
	bash -c "\
		SYFT_VERSION=$(SYFT_VERSION)\
			$(RELEASE_CMD) \
				--config $(TEMPDIR)/goreleaser.yaml \
				--parallelism 1 \
				--release-notes <(cat CHANGELOG.md)\
					 || (cat .github/scripts/apple-signing/log/*.txt && false)"

	cat .github/scripts/apple-signing/log/*.txt

	# TODO: turn this into a post-release hook
	# upload the version file that supports the application version update check (excluding pre-releases)
	.github/scripts/update-version-file.sh "$(DISTDIR)" "$(VERSION)"

.PHONY: clean
clean: clean-dist clean-snapshot  ## Remove previous builds and result reports
	$(call safe_rm_rf_children,$(RESULTSDIR))

.PHONY: clean-snapshot
clean-snapshot:
	$(call safe_rm_rf,$(SNAPSHOTDIR))
	rm -f $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-dist
clean-dist: clean-changelog
	$(call safe_rm_rf,$(DISTDIR))
	rm -f $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-changelog
clean-changelog:
	rm -f CHANGELOG.md

.PHONY: clean-test-cache
clean-test-cache: ## Delete all test cache (built docker image tars)
	find . -type f -wholename "**/test-fixtures/cache/*.tar" -delete
