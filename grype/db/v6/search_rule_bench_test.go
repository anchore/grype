package v6

import (
	"fmt"
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// The benchmarks here measure the whole criteria -> queries-to-run path, not applySearchRules alone.
// That composite is what the matchers actually pay for on every search, and measuring it as a unit is
// what keeps the numbers comparable as the resolution internals move around underneath.

// benchExactNamePattern builds a rule pattern that selects exactly one package name. It exists so the
// synthetic rule sets below keep meaning "one exact-name rule per package" regardless of how rule
// patterns are anchored — patterns are anchored on compile, so the name alone is an exact match.
func benchExactNamePattern(name string) string {
	return name
}

// benchResolve is the operation under test: criteria in, the queries to actually run out.
func benchResolve(b *testing.B, rules *searchRuleIndex, criteria []vulnerability.Criteria) {
	b.Helper()
	for b.Loop() {
		if _, err := newSearchQueries(criteria, rules); err != nil {
			b.Fatal(err)
		}
	}
}

// benchSyntheticRules pads the built-in set with per-package exact-name routing rules, which is the
// shape the table is expected to grow into (see the TODO on KnownSearchRules): many rules under a
// single distro, each speaking for one package.
func benchSyntheticRules(count int) []SearchRule {
	rules := KnownSearchRules()
	for i := 0; i < count; i++ {
		rules = append(rules, SearchRule{
			MatchDistroName:    "rapidfort-redhat",
			MatchPackageName:   benchExactNamePattern(fmt.Sprintf("synthetic-pkg-%d", i)),
			ReplacementChannel: ptr(fmt.Sprintf("synth%d", i)),
			IncludeBaseDistro:  ptr(false),
		})
	}
	return rules
}

func BenchmarkResolveSearchQueries(b *testing.B) {
	ruleSets := []struct {
		name  string
		rules []SearchRule
	}{
		{name: "builtin", rules: KnownSearchRules()},
		{name: "synthetic-500", rules: benchSyntheticRules(500)},
	}

	criteriaSets := []struct {
		name     string
		criteria []vulnerability.Criteria
	}{
		{
			// the overwhelmingly common case: no rule speaks for this package at all
			name: "debian-no-match",
			criteria: []vulnerability.Criteria{
				search.ByPackageName("openssl"),
				search.ByDistro(*distro.New(distro.Debian, "12", "bookworm")),
				search.WithVersion(*version.New("1.1.1n-0+deb11u4", version.DebFormat)),
			},
		},
		{
			// a rule matches and rewrites the queried OS to a release-stream channel
			name: "rapidfort-fc-tag",
			criteria: []vulnerability.Criteria{
				search.ByPackageName("curl"),
				search.ByDistro(*distro.New(distro.RapidFortRedHat, "9", "")),
				search.WithVersion(*version.New("7.78.0-3.fc43", version.RpmFormat)),
			},
		},
		{
			// the OS-scoped data policy rule: matches, but substitutes nothing
			name: "rapidfort-alpine-data-policy",
			criteria: []vulnerability.Criteria{
				search.ByPackageName("busybox"),
				search.ByDistro(*distro.New(distro.RapidFortAlpine, "3.19", "")),
				search.WithVersion(*version.New("1.36.1-r15", version.ApkFormat)),
			},
		},
		{
			// an OS-less ecosystem query that fans out into an additional OS-scoped query
			name: "deb-ecosystem-echo",
			criteria: []vulnerability.Criteria{
				search.ByEcosystem("", "deb"),
				search.ByPackageName("openssl"),
				search.ByVersion(*version.New("1.1.1n-0+deb11u4.echo1", version.DebFormat)),
			},
		},
	}

	for _, rs := range ruleSets {
		compiled := newSearchRuleIndex(rs.rules)
		for _, cs := range criteriaSets {
			b.Run(rs.name+"/"+cs.name, func(b *testing.B) {
				benchResolve(b, compiled, cs.criteria)
			})
		}
	}
}
