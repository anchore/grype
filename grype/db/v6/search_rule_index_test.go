package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// linearMatchingRules is what matchingRules did before the index existed: evaluate every rule in the
// set, in the order it was read. TestSearchRuleIndex_MatchesLinearScan holds the index to this.
func linearMatchingRules(idx *searchRuleIndex, p pkg.Package) []*compiledSearchRule {
	var matched []*compiledSearchRule
	for _, r := range idx.rules {
		if r.matches(p) {
			matched = append(matched, r)
		}
	}
	return matched
}

func ordsOf(rules []*compiledSearchRule) []int {
	out := make([]int, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ord)
	}
	return out
}

// TestSearchRuleIndex_MatchesLinearScan is the safety argument for indexing: narrowing the candidate
// set must not change which rules apply, nor the order they apply in — rule order decides the order of
// the searches they resolve to, and so reaches grype's output.
func TestSearchRuleIndex_MatchesLinearScan(t *testing.T) { //nolint:funlen // one fixture rule set plus the package shapes it has to cover
	// the built-ins, plus shapes they do not exercise
	rows := append(KnownSearchRules(),
		// unscoped: no distro name and no ecosystem, so it is a candidate for every query
		SearchRule{MatchPackageName: `unscoped-.*`, ReplacementPackageName: "vendor-$0"},
		// distro version predicate with no distro name
		SearchRule{MatchDistroVersion: `9.*`, MatchPackageName: `.*`, ReplacementPackageName: "byver-$0"},
		// an uppercase distro name, which must still be found by a lowercase lookup
		SearchRule{MatchDistroName: "RapidFort-RedHat", MatchPackageName: `upper-.*`, ReplacementChannel: ptr("upper"), Priority: 99},
		// exact package names, several under one distro
		SearchRule{MatchDistroName: "debian", MatchPackageName: `curl`, ReplacementPackageName: "curl-exact"},
		SearchRule{MatchDistroName: "debian", MatchPackageName: `curl`, ReplacementPackageName: "curl-also"},
		// an ecosystem-scoped rule with an exact name
		SearchRule{MatchEcosystem: "apk", MatchPackageName: `busybox`, ReplacementPackageName: "busybox-alt"},
	)
	idx := newSearchRuleIndex(rows)
	require.Len(t, idx.rules, len(rows), "every rule in this fixture must compile")

	debian := distro.New(distro.Debian, "11", "")
	rfRedhat := distro.New(distro.RapidFortRedHat, "9", "")
	rfRedhatEUS := distro.New(distro.RapidFortRedHat, "9", "")
	rfRedhatEUS.Channels = []string{"eus"}

	packages := map[string]pkg.Package{
		"no OS at all": {
			Name:    "curl",
			Version: "1.2.3-4",
		},
		"one OS": {
			Name:    "curl",
			Version: "1.2.3-4",
			Distro:  debian,
		},
		"one OS, exact-name rules apply": {
			Name:    "curl",
			Version: "1.1.1n-0+deb11u4.echo1",
			Distro:  debian,
		},
		"a distro carrying a channel": {
			Name:    "curl",
			Version: "7.78.0-3.fc43",
			Distro:  rfRedhatEUS,
		},
		"uppercase rule reached by a lowercase distro name": {
			Name:    "upper-thing",
			Version: "1.0-1",
			Distro:  rfRedhat,
		},
		"an unknown distro type no rule speaks for": {
			Name:    "curl",
			Version: "1.0-1",
			Distro:  distro.New(distro.Type("not-a-real-distro"), "1", ""),
		},
		"ecosystem only": {
			Name:    "busybox",
			Version: "1.36.1-r15",
			Type:    syftPkg.ApkPkg,
		},
		"ecosystem and OS together": {
			Name:    "openssl",
			Version: "1.1.1n-0+deb11u4.echo1",
			Type:    syftPkg.DebPkg,
			Distro:  debian,
		},
		"no package name": {
			Version: "7.78.0-3.fc43",
			Distro:  rfRedhat,
		},
		"no version": {
			Name:   "rf-scanner",
			Distro: rfRedhat,
		},
	}

	for name, p := range packages {
		t.Run(name, func(t *testing.T) {
			want := linearMatchingRules(idx, p)
			got := matchingRules(idx, p)
			assert.Equal(t, ordsOf(want), ordsOf(got),
				"the index selected different rules (or a different order) than a linear scan")
		})
	}
}

// TestSearchRuleIndex_FilesEveryRuleExactlyOnce guards the disjointness the candidate gathering relies
// on: a rule reachable through two buckets would be evaluated — and applied — twice.
func TestSearchRuleIndex_FilesEveryRuleExactlyOnce(t *testing.T) {
	idx := newSearchRuleIndex(append(KnownSearchRules(),
		SearchRule{MatchPackageName: `unscoped-.*`, ReplacementPackageName: "vendor-$0"},
		// a rule with both a distro name and an ecosystem: filed under the distro alone
		SearchRule{MatchDistroName: "debian", MatchEcosystem: "deb", MatchPackageName: `curl`, ReplacementPackageName: "x"},
	))

	filed := map[int]int{}
	count := func(rules []*compiledSearchRule) {
		for _, r := range rules {
			filed[r.ord]++
		}
	}
	for _, b := range idx.byDistroName {
		count(b)
	}
	for _, b := range idx.byEcosystem {
		count(b)
	}
	count(idx.unscoped)

	require.Len(t, filed, len(idx.rules), "every rule must be filed somewhere")
	for _, r := range idx.rules {
		assert.Equalf(t, 1, filed[r.ord], "rule %d is filed in more than one bucket", r.ord)
	}
}
