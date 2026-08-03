# Builds the Go binary fixtures used by the gosymbols matcher tests. These are
# real, compiled Go programs so their captured function symbols (via syft's
# SYFT_GOLANG_CAPTURE_SYMBOLS) are exactly what grype sees in the field.
#
# The gosymbols matcher test builds these on demand (dbtest.GoBinaryFixture shells
# out to `make` in each fixture dir), so no separate build step is required. This
# top-level Makefile is the single build entrypoint and follows go-make's fixture
# convention (**/testdata/Makefile), so it can be wired into `make fixtures`/`unit`
# later if desired. Built binaries are gitignored per fixture dir; sources +
# go.mod/go.sum are committed so builds are reproducible (the x/net fixtures fetch
# a pinned, checksummed module).

FIXTURE_DIRS := $(wildcard gobin-*)

.DEFAULT_GOAL := fixtures

.PHONY: fixtures clean $(FIXTURE_DIRS)
fixtures: $(FIXTURE_DIRS)

$(FIXTURE_DIRS):
	$(MAKE) -C $@

clean:
	@for dir in $(FIXTURE_DIRS); do $(MAKE) -C $$dir clean; done
