TEMPDIR = ./.tmp
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --config .golangci.yaml
BOLD := $(shell tput bold)
PURPLE := $(shell tput setaf 5)
GREEN := $(shell tput setaf 2)
RESET := $(shell tput sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

ifndef TEMPDIR
$(error TEMPDIR is not set)
endif

.PHONY: all boostrap lint lint-fix unit coverage integration build-release

all: lint unit integration
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

bootstrap:
	@printf '$(TITLE)Downloading dependencies$(RESET)\n'
	# install project dependencies
	go get ./...
	mkdir -p $(TEMPDIR)
	# install golangci-lint
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b .tmp/ v1.26.0
	# install go-acc
	GOPATH=$(shell realpath ${TEMPDIR}) GO111MODULE=off go get github.com/ory/go-acc
	# cleanup
	rm -rf $(TEMPDIR)/src

lint:
	@printf '$(TITLE)Running linters$(RESET)\n'
	test -z "$(shell gofmt -l -s .)"
	$(LINTCMD)

lint-fix:
	@printf '$(TITLE)Running lint fixers$(RESET)\n'
	gofmt -w -s .
	$(LINTCMD) --fix

unit:
	@printf '$(TITLE)Running unit tests$(RESET)\n'
	go test --race ./...

coverage:
	@printf '$(TITLE)Running unit tests + coverage$(RESET)\n'
	$(TEMPDIR)/bin/go-acc -o $(TEMPDIR)/coverage.txt ./...

# TODO: add benchmarks

integration:
	@printf '$(TITLE)Running integration tests...$(RESET)\n'
	go test -tags=integration ./integration

build-release:
	go build -s -w -X main.version="$(git describe --tags --dirty --always)" \
				   -X main.commit="$(git describe --dirty --always)" \
				   -X main.buildTime="$(date --rfc-3339=seconds --utc)"
