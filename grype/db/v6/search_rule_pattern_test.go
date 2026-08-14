package v6

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacySearchRulePatterns records every pattern in KnownSearchRules alongside the pre-anchoring form
// it replaced. Before rule patterns were anchored (see anchorPattern) they matched anywhere in the
// subject, so each one had to be rewritten with explicit wildcards; this table plus the test below is
// the only written record that the rewrites preserved the original semantics.
//
// This can be deleted once rules come from the DB rather than from KnownSearchRules — at that point
// there is no in-tree pattern left for it to speak about.
var legacySearchRulePatterns = []struct {
	name string

	// legacy is the pattern as it was written when patterns matched substrings
	legacy string

	// anchored is the pattern as it now appears in KnownSearchRules, before anchorPattern wraps it
	anchored string

	// capturing marks a pattern whose capture group feeds a $N substitution, so agreement on the
	// captured value matters and not just on whether the pattern matched
	capturing bool
}{
	{
		name:     "rpm rf rebuild marker",
		legacy:   `\.rf(?:[._~-]|$)`,
		anchored: `.*\.rf(?:[._~-].*)?`,
	},
	{
		name:     "dpkg rf rebuild marker",
		legacy:   `rfubu|rfdeb|[.+~-]rf(?:[._]|$)`,
		anchored: rapidfortDpkgRebuildMarker,
	},
	{
		name:      "fedora dist tag",
		legacy:    `\.fc(\d+)(?:[._~-]|$)`,
		anchored:  `.*?\.fc(\d+)(?:[._~-].*)?`,
		capturing: true,
	},
	{
		name:     "rf name prefix",
		legacy:   `^rf-`,
		anchored: `rf-.*`,
	},
	{
		name:     "el dist tag exclusion",
		legacy:   `\.el\d+(?:[._~-]|$)`,
		anchored: `.*\.el\d+(?:[._~-].*)?`,
	},
	{
		name:     "echo version marker",
		legacy:   `[.-]echo`,
		anchored: `.*[.-]echo.*`,
	},
}

// searchRulePatternSubjects is a corpus of package versions and names to compare the legacy and
// anchored patterns over. The realistic entries are drawn from RapidFort's published advisory data
// and cover every release-stream marker; the rest are near-misses that the legacy patterns
// deliberately reject, which is where a careless wildcard rewrite would show up.
var searchRulePatternSubjects = []string{
	// fedora stream
	"0.0.10-1.fc43", "0.0.19-6.fc42", "1.0.0~rc-10.fc43", "7.78.0-3.fc43", "1:12.6.0-2.fc31~bootstrap",
	// native el stream
	"0.0.99.3-10.el9_2", "0.0.99.3-5.el9", "0:7.76.1-19.el9_2", "1.20.3-1.el9",
	// rpm rf rebuilds, including one carrying both an fc and an rf marker
	"0.02-533.rf", "1:3.2.2-20.rf", "1:12.6.0-2.fc31.rf.1", "10.4p1-12.fc45.rf",
	// dpkg rf rebuilds, across both of RapidFort's naming schemes
	"0.25.3-10rfubu", "1.0.8-15rfubu1", "1.11.0-6rfubuntu1+rf.1", "1.30+dfsg-7rfubu.1",
	"1.2-4rfdebian~rf.1", "1.2-4~rf",
	// echo-patched debs
	"1.1.1n-0+deb11u4.echo1", "1.1.1n-0-echo1",
	// unmarked versions (the native stream, which no rule should claim)
	"0.087-1", "0.09-3ubuntu0.25.10.1", "0.1.2+24.04", "1.2.3-4",
	"0.1.27+ds-1+deb10u2build0.20.04.1",
	// near-misses: a marker that is present but not terminated, or not at a boundary
	"1.2-3.rfoo", "1.2-4~rfx", "xrf-foo", "1.0-1.el", "1.0-1.fc", "1.0-1.rf",
	"rf", "rf-", "aechob", "echo", ".echo", "-echo",
	// two dist tags: the only subjects that can tell a greedy leading wildcard from a lazy one
	"1.2-3.fc31.fc43", "2.0.fc9.fc10-1",
	// package names
	"rf-scanner", "rf-curl", "rf-wget", "curl", "openssl", "busybox", "librf-dev",
}

func TestKnownSearchRules_AnchoredPatternsMatchLegacySemantics(t *testing.T) {
	for _, tt := range legacySearchRulePatterns {
		t.Run(tt.name, func(t *testing.T) {
			legacy := regexp.MustCompile(tt.legacy)
			anchored := regexp.MustCompile(anchorPattern(tt.anchored))

			var matched int
			for _, subject := range searchRulePatternSubjects {
				want := legacy.MatchString(subject)
				assert.Equalf(t, want, anchored.MatchString(subject),
					"anchored pattern disagrees with the legacy pattern on %q", subject)
				if !want {
					continue
				}
				matched++

				if !tt.capturing {
					continue
				}
				// $N expansion binds to whichever occurrence the engine chose, so the captured value
				// has to agree too — this is what distinguishes `.*?` from `.*` in front of a group
				wantGroups := legacy.FindStringSubmatch(subject)
				gotGroups := anchored.FindStringSubmatch(subject)
				require.Len(t, wantGroups, 2)
				require.Len(t, gotGroups, 2)
				assert.Equalf(t, wantGroups[1], gotGroups[1],
					"anchored pattern captured a different group than the legacy pattern on %q", subject)
			}

			// a pattern that matches nothing in the corpus proves nothing about the rewrite
			assert.NotZerof(t, matched, "no subject in the corpus matched %q", tt.legacy)
		})
	}
}

// TestKnownSearchRules_PatternsAreAllCoveredByLegacyTable keeps the table above from going stale: a
// pattern added to or edited in KnownSearchRules without a matching entry has no equivalence
// evidence behind it.
func TestKnownSearchRules_PatternsAreAllCoveredByLegacyTable(t *testing.T) {
	covered := make(map[string]struct{}, len(legacySearchRulePatterns))
	for _, tt := range legacySearchRulePatterns {
		covered[tt.anchored] = struct{}{}
	}

	for _, row := range KnownSearchRules() {
		for _, pattern := range []string{
			row.MatchDistroVersion, row.MatchPackageName, row.ExcludePackageName,
			row.MatchPackageVersion, row.ExcludePackageVersion,
		} {
			if pattern == "" {
				continue
			}
			assert.Containsf(t, covered, pattern,
				"pattern %q in KnownSearchRules has no entry in legacySearchRulePatterns", pattern)
		}
	}
}
