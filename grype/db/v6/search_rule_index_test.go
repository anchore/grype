package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// matchedOrders returns the read order of each matched rule, with what it captured.
func matchedOrders(matched []matchedRule) []orderCaptures {
	var out []orderCaptures
	for _, m := range matched {
		out = append(out, orderCaptures{m.rule.order, m.captures})
	}
	return out
}

type orderCaptures struct {
	order    int
	captures []capture
}

// unsharedMatches is the reference the index must agree with: each rule matched in an index of its
// own, so no rule shares a node with another.
func unsharedMatches(rows []SearchRule, s searchSubject) []orderCaptures {
	var out []orderCaptures
	for i, row := range rows {
		for _, m := range newSearchIndex([]SearchRule{row}).matchingRules(s) {
			out = append(out, orderCaptures{i, m.captures})
		}
	}
	return out
}

// Sharing nodes must not change which rules match, their order (which decides search order
// and so reaches grype's output) or what they capture.
func TestSearchIndex_MatchesUnshared(t *testing.T) { //nolint:funlen // one fixture rule set plus the package shapes it has to cover
	rows := append(KnownSearchRules(),
		// regex distro name, filed under its ecosystem
		SearchRule{MatchDistroName: `rapidfort-.*`, MatchEcosystem: "rpm", MatchPackageName: `.*`, ReplacementPackageName: "rf-${package_name}"},
		// distro version pattern with no distro name
		SearchRule{MatchEcosystem: "rpm", MatchDistroVersion: `9.*`, MatchPackageName: `.*`, ReplacementPackageName: "byver-${package_name}"},
		// shares the regexMatch nodes of the rule above
		SearchRule{MatchEcosystem: "rpm", MatchDistroVersion: `9.*`, MatchPackageName: `.*`, ExcludePackageName: `openssl`, ReplacementPackageName: "byver2-${package_name}"},
		// uppercase distro name
		SearchRule{MatchDistroName: "RapidFort-RedHat", MatchPackageName: `upper-.*`, ReplacementChannel: ptr("upper"), Priority: 99},
		// several exact package names under one distro, filed under the package name
		SearchRule{MatchDistroName: "debian", MatchPackageName: `curl`, ReplacementPackageName: "curl-exact"},
		SearchRule{MatchDistroName: "debian", MatchPackageName: `curl`, ReplacementPackageName: "curl-also"},
		// ecosystem-scoped with an exact name
		SearchRule{MatchEcosystem: "apk", MatchPackageName: `busybox`, ReplacementPackageName: "busybox-alt"},
	)
	requireAllValid(t, rows)
	idx := newSearchIndex(rows)

	debian := distro.New(distro.Debian, "11", "")
	rfRedhat := distro.New(distro.RapidFortRedHat, "9", "")
	rfRedhatEUS := distro.New(distro.RapidFortRedHat, "9", "")
	rfRedhatEUS.Channels = []string{"eus"}

	subjects := map[string]searchSubject{
		"no OS at all": {
			name:    "curl",
			version: "1.2.3-4",
		},
		"one OS": {
			name:    "curl",
			version: "1.2.3-4",
			distro:  debian,
		},
		"a distro carrying a channel": {
			name:    "curl",
			version: "7.78.0-3.fc43",
			distro:  rfRedhatEUS,
		},
		"uppercase rule reached by a lowercase distro name": {
			name:    "upper-thing",
			version: "1.0-1",
			distro:  rfRedhat,
		},
		"an unknown distro type no rule speaks for": {
			name:    "curl",
			version: "1.0-1",
			distro:  distro.New(distro.Type("not-a-real-distro"), "1", ""),
		},
		"ecosystem only": {
			name:      "busybox",
			version:   "1.36.1-r15",
			ecosystem: string(syftPkg.ApkPkg),
		},
		"ecosystem and OS together": {
			name:      "openssl",
			version:   "1.1.1n-0+deb11u4.echo1",
			ecosystem: string(syftPkg.DebPkg),
			distro:    debian,
		},
		"no package name": {
			version: "7.78.0-3.fc43",
			distro:  rfRedhat,
		},
		"a regex distro name": {
			name:      "openssl",
			version:   "3.0.7-1",
			ecosystem: string(syftPkg.RpmPkg),
			distro:    rfRedhat,
		},
		"no version": {
			name:   "rf-scanner",
			distro: rfRedhat,
		},
	}

	matchedAny := false
	for name, s := range subjects {
		t.Run(name, func(t *testing.T) {
			want := unsharedMatches(rows, s)
			matchedAny = matchedAny || len(want) > 0
			assert.Equal(t, want, matchedOrders(idx.matchingRules(s)),
				"the shared index matched different rules, order or captures than each rule alone")
		})
	}
	assert.True(t, matchedAny, "the fixture must exercise some matches")
}

// Rules with the same pattern at the same place share its regexMatch, which runs once.
func TestSearchIndex_SharesRegexMatches(t *testing.T) {
	idx := newSearchIndex([]SearchRule{
		{MatchDistroName: "debian", MatchPackageVersion: `.*\+rf.*`, ReplacementChannel: ptr("a")},
		{MatchDistroName: "debian", MatchPackageVersion: `.*\+rf.*`, ExcludePackageName: "curl", ReplacementChannel: ptr("b")},
		{MatchDistroName: "debian", MatchPackageVersion: `.*\+echo.*`, ReplacementChannel: ptr("c")},
	})
	debian := idx.byDistroName["debian"]
	require.NotNil(t, debian)
	assert.Equal(t, []patternNode{
		nodeOf(t, packageVersion, false, `.*\+rf.*`),
		nodeOf(t, packageVersion, false, `.*\+echo.*`),
	}, patternsOf(debian.remaining), "one regexMatch per distinct version pattern")

	rf := debian.remaining[0]
	assert.Len(t, rf.matches, 1, "the rule ending at the shared pattern")
	assert.Equal(t, []patternNode{nodeOf(t, packageName, true, "curl")}, patternsOf(rf.next), "the exclude follows the shared pattern")

	matched := idx.matchingRules(searchSubject{name: "curl", version: "1.0-1+rf1", distro: distro.New(distro.Debian, "12", "")})
	assert.Equal(t, []orderCaptures{{0, nil}}, matchedOrders(matched),
		"the exclude after the shared pattern rejects only its own rule")
}

func TestSearchIndex_ExactOrRegexPatterns(t *testing.T) {
	rfUbuntu := distro.New(distro.RapidFortUbuntu, "20.04", "")

	tests := []struct {
		name    string
		row     SearchRule
		subject searchSubject
		want    bool
	}{
		{
			name:    "an exact distro name and ecosystem ignore case",
			row:     SearchRule{MatchDistroName: "RapidFort-Ubuntu", MatchEcosystem: "DEB", ReplacementChannel: ptr("rf")},
			subject: searchSubject{name: "curl", ecosystem: "deb", distro: rfUbuntu},
			want:    true,
		},
		{
			name:    "a regex distro name ignores case",
			row:     SearchRule{MatchDistroName: `RAPIDFORT-.*`, MatchEcosystem: "deb", ReplacementDistroName: ptr("x")},
			subject: searchSubject{name: "curl", ecosystem: "deb", distro: rfUbuntu},
			want:    true,
		},
		{
			name:    "a regex distro name is anchored",
			row:     SearchRule{MatchDistroName: `rapidfort`, MatchEcosystem: "deb", ReplacementDistroName: ptr("x")},
			subject: searchSubject{name: "curl", ecosystem: "deb", distro: rfUbuntu},
			want:    false,
		},
		{
			name:    "an exact package name ignores case",
			row:     SearchRule{MatchPackageName: "Curl", ReplacementPackageName: "x"},
			subject: searchSubject{name: "curl", ecosystem: "deb"},
			want:    true,
		},
		{
			name:    "a regex package name ignores case",
			row:     SearchRule{MatchPackageName: `LIB.*`, MatchEcosystem: "deb", ReplacementPackageName: "x"},
			subject: searchSubject{name: "libcurl", ecosystem: "deb"},
			want:    true,
		},
		{
			name:    "an exact exclude package name ignores case",
			row:     SearchRule{MatchPackageName: `.*`, ExcludePackageName: "CURL", MatchEcosystem: "deb", ReplacementPackageName: "x"},
			subject: searchSubject{name: "curl", ecosystem: "deb"},
			want:    false,
		},
		{
			name:    "an exact package version",
			row:     SearchRule{MatchEcosystem: "deb", MatchPackageVersion: "7.68.0-1", ReplacementPackageName: "x", MatchPackageName: "curl"},
			subject: searchSubject{name: "curl", version: "7.68.0-1", ecosystem: "deb"},
			want:    true,
		},
		{
			name:    "an exact exclude rejects only its value",
			row:     SearchRule{MatchPackageName: `.*`, ExcludePackageName: "curl", MatchEcosystem: "deb", ReplacementPackageName: "x"},
			subject: searchSubject{name: "curl2", ecosystem: "deb"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireAllValid(t, []SearchRule{tt.row})
			assert.Equal(t, tt.want, len(newSearchIndex([]SearchRule{tt.row}).matchingRules(tt.subject)) == 1)
		})
	}
}

// patternNode is a regexMatch as a test compares it: its match type and compiled pattern.
type patternNode struct {
	matchType
	negate bool
	regex  string
}

func nodeOf(t *testing.T, mt matchType, negate bool, pattern string) patternNode {
	t.Helper()
	re, _, err := compilePattern(pattern)
	require.NoError(t, err)
	return patternNode{mt, negate, re.String()}
}

func patternsOf(rms []*regexMatch) []patternNode {
	out := make([]patternNode, 0, len(rms))
	for _, rm := range rms {
		out = append(out, patternNode{rm.matchType, rm.negate, rm.regex.String()})
	}
	return out
}

// matchingRules returns the rules s matches, in read order.
func (n *searchIndex) matchingRules(s searchSubject) []matchedRule {
	return n.appendMatchingRules(nil, s)
}
