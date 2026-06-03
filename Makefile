.PHONY: test
test:
	@go run -C .make . test

.PHONY: snapshot
snapshot:
	@go run -C .make . snapshot

.PHONY: *
.DEFAULT_GOAL: make-default

make-default:
	@go run -C .make .

.PHONY: *
.DEFAULT:
%:
	@go run -C .make . $@
