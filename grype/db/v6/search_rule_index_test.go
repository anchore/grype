package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	syftPkg "github.com/anchore/syft/syft/pkg"
)

// linearMatchingRules is what matchingRules did before the index existed: evaluate every rule in the
// set, in the order it was read. TestSearchRuleIndex_MatchesLinearScan holds the index to this.
func linearMatchingRules(idx *searchRuleIndex, q *searchQuery) []*compiledSearchRule {
	var matched []*compiledSearchRule
	for _, r := range idx.rules {
		if r.matches(q) {
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
// the resolved OS specifiers and of the fanned-out queries, and so reaches grype's output.
func TestSearchRuleIndex_MatchesLinearScan(t *testing.T) { //nolint:funlen // one fixture rule set plus the query shapes it has to cover
	// the built-ins, plus shapes they do not exercise
	rows := append(KnownSearchRules(),
		// unscoped: no distro name and no ecosystem, so it is a candidate for every query
		SearchRule{MatchPackageName: `unscoped-.*`, ReplacementPackageName: "vendor-$0"},
		// distro version predicate with no distro name
		SearchRule{MatchDistroVersion: `9.*`, MatchPackageName: `.*`, ReplacementPackageName: "byver-$0"},
		// an uppercase distro name, which must still be found by a lowercase lookup
		SearchRule{MatchDistroName: "RapidFort-RedHat", MatchPackageName: `upper-.*`, ReplacementChannel: ptr("upper"), Priority: 99},
		// an exact package name, which the index files in a bucket's name sub-index
		SearchRule{MatchDistroName: "debian", MatchPackageName: `curl`, ReplacementPackageName: "curl-exact"},
		// a second rule on the same exact name, so the sub-index holds more than one
		SearchRule{MatchDistroName: "debian", MatchPackageName: `curl`, ReplacementPackageName: "curl-also"},
		// an ecosystem-scoped rule with an exact name
		SearchRule{MatchEcosystem: "apk", MatchPackageName: `busybox`, ReplacementPackageName: "busybox-alt"},
	)
	idx := newSearchRuleIndex(rows)
	require.Len(t, idx.rules, len(rows), "every rule in this fixture must compile")

	debian := osSpec("debian", "11", "")
	rfRedhat := osSpec("rapidfort-redhat", "9", "")

	queries := map[string]*searchQuery{
		"no OS at all": {
			pkgSpec: &PackageSpecifier{Name: "curl"},
			osSpecs: OSSpecifiers{NoOSSpecified},
			version: "1.2.3-4",
		},
		"the any-OS specifier": {
			pkgSpec: &PackageSpecifier{Name: "curl"},
			osSpecs: OSSpecifiers{AnyOSSpecified},
			version: "1.2.3-4",
		},
		"one OS": {
			pkgSpec: &PackageSpecifier{Name: "curl"},
			osSpecs: OSSpecifiers{debian},
			version: "1.2.3-4",
		},
		"one OS, exact-name rules apply": {
			pkgSpec: &PackageSpecifier{Name: "curl"},
			osSpecs: OSSpecifiers{debian},
			version: "1.1.1n-0+deb11u4.echo1",
		},
		"two OS specifiers with different names": {
			pkgSpec: &PackageSpecifier{Name: "curl"},
			osSpecs: OSSpecifiers{debian, rfRedhat},
			version: "7.78.0-3.fc43",
		},
		"two OS specifiers sharing a name (base plus channel)": {
			pkgSpec: &PackageSpecifier{Name: "curl"},
			osSpecs: OSSpecifiers{rfRedhat, osSpec("rapidfort-redhat", "9", "eus")},
			version: "7.78.0-3.fc43",
		},
		"uppercase rule reached by a lowercase specifier": {
			pkgSpec: &PackageSpecifier{Name: "upper-thing"},
			osSpecs: OSSpecifiers{rfRedhat},
			version: "1.0-1",
		},
		"an unknown distro type no rule speaks for": {
			pkgSpec: &PackageSpecifier{Name: "curl"},
			osSpecs: OSSpecifiers{osSpec("not-a-real-distro", "1", "")},
			version: "1.0-1",
		},
		"ecosystem only": {
			pkgSpec: &PackageSpecifier{Name: "busybox", Ecosystem: "apk"},
			pkgType: syftPkg.ApkPkg,
			osSpecs: OSSpecifiers{NoOSSpecified},
			version: "1.36.1-r15",
		},
		"ecosystem and OS together, as a package view carries them": {
			pkgSpec: &PackageSpecifier{Name: "openssl", Ecosystem: "deb"},
			pkgType: syftPkg.DebPkg,
			osSpecs: OSSpecifiers{debian},
			version: "1.1.1n-0+deb11u4.echo1",
		},
		"no package name": {
			pkgSpec: &PackageSpecifier{},
			osSpecs: OSSpecifiers{rfRedhat},
			version: "7.78.0-3.fc43",
		},
		"no version": {
			pkgSpec: &PackageSpecifier{Name: "rf-scanner"},
			osSpecs: OSSpecifiers{rfRedhat},
		},
	}

	for name, q := range queries {
		t.Run(name, func(t *testing.T) {
			want := linearMatchingRules(idx, q)
			got := matchingRules(idx, q)
			assert.Equal(t, ordsOf(want), ordsOf(got),
				"the index selected different rules (or a different order) than a linear scan")
		})
	}
}

func osSpec(name, majorMinor, channel string) *OSSpecifier {
	spec := &OSSpecifier{Name: name, Channel: channel}
	for i, part := range splitVersionParts(majorMinor) {
		switch i {
		case 0:
			spec.MajorVersion = part
		case 1:
			spec.MinorVersion = part
		case 2:
			spec.RemainingVersion = part
		}
	}
	return spec
}

func splitVersionParts(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	cur := ""
	for _, r := range v {
		if r == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
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
	count := func(bucket *ruleBucket) {
		for _, rules := range bucket.byExactName {
			for _, r := range rules {
				filed[r.ord]++
			}
		}
		for _, r := range bucket.rest {
			filed[r.ord]++
		}
	}
	for _, b := range idx.byDistroName {
		count(b)
	}
	for _, b := range idx.byEcosystem {
		count(b)
	}
	count(&idx.unscoped)

	require.Len(t, filed, len(idx.rules), "every rule must be filed somewhere")
	for _, r := range idx.rules {
		assert.Equalf(t, 1, filed[r.ord], "rule %d is filed in more than one bucket", r.ord)
	}
}
