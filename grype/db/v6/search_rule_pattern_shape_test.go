package v6

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPatternShape(t *testing.T) { //nolint:funlen // table-driven over each pattern shape
	tests := []struct {
		name    string
		pattern string // as a rule author writes it, before anchorPattern wraps it
		want    patternShape
	}{
		{
			name:    "a bare literal is an exact match",
			pattern: `curl`,
			want:    patternShape{exact: "curl"},
		},
		{
			name:    "a literal wrapped in a capture group is still exact",
			pattern: `(curl)`,
			want:    patternShape{exact: "curl"},
		},
		{
			name:    "a literal followed by a wildcard constrains the prefix",
			pattern: `rf-.*`,
			want:    patternShape{prefix: "rf-"},
		},
		{
			name:    "a marker behind a lazy wildcard must appear somewhere",
			pattern: `.*?\.fc(\d+)(?:[._~-].*)?`,
			want:    patternShape{needle: ".fc"},
		},
		{
			name:    "a marker behind a greedy wildcard must appear somewhere",
			pattern: `.*\.rf(?:[._~-].*)?`,
			want:    patternShape{needle: ".rf"},
		},
		{
			name:    "the longest top-level literal is preferred",
			pattern: `.*[.-]echo.*`,
			want:    patternShape{needle: "echo"},
		},
		{
			name:    "a class before a literal still yields the literal as a needle",
			pattern: `.*\.el\d+(?:[._~-].*)?`,
			want:    patternShape{needle: ".el"},
		},
		{
			name: "an alternation keeps a claim all its branches share",
			// the rf-dpkg marker: the parser factors `rfubu|rfdeb` down to `rf(?:ubu|deb)`, so both
			// branches require an "rf" and the shared needle survives
			pattern: rapidfortDpkgRebuildMarker,
			want:    patternShape{needle: "rf"},
		},
		{
			name:    "an alternation whose branches share a needle keeps it",
			pattern: `.*ab.*|.*ab`,
			want:    patternShape{needle: "ab"},
		},
		{
			name:    "an alternation whose branches disagree claims nothing",
			pattern: `foo|bar`,
			want:    patternShape{},
		},
		{
			name: "a factored alternation degrades to the weaker claim",
			// the parser rewrites this to `foo(?:)`, so the body is a concatenation rather than a
			// single literal and the shape is a prefix instead of an exact match. Weaker than it
			// could be, but never wrong — which is the only property that matters here.
			pattern: `foo|foo`,
			want:    patternShape{prefix: "foo"},
		},
		{
			name:    "a leading wildcard alone claims nothing",
			pattern: `.*`,
			want:    patternShape{},
		},
		{
			name:    "a leading character class alone claims nothing",
			pattern: `\d+`,
			want:    patternShape{},
		},
		{
			name: "a case-insensitive literal is not a plain comparison",
			// the parser case-folds the runes (to "CURL" here), so a plain comparison against the
			// subject would be wrong outright rather than merely weak
			pattern: `(?i)curl`,
			want:    patternShape{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, newPatternShape(anchorPattern(tt.pattern)))
		})
	}
}

func TestNewPatternShape_UnanchoredPatternClaimsNothing(t *testing.T) {
	// a shape is only sound for a pattern that describes the whole subject; handed an unanchored one
	// it must decline rather than make a claim the pattern does not support
	assert.Equal(t, patternShape{}, newPatternShape(`rf-.*`))
	assert.Equal(t, patternShape{}, newPatternShape(`^rf-`))
	assert.Equal(t, patternShape{}, newPatternShape(`rf-.*$`))
}

func TestNewPatternShape_InvalidPatternClaimsNothing(t *testing.T) {
	assert.Equal(t, patternShape{}, newPatternShape(anchorPattern(`(`)))
}

// patternShapeSubjects extends the realistic version corpus with plain strings, so the property below
// is exercised by the hand-written patterns too rather than only by the release-stream markers.
func patternShapeSubjects() []string {
	return append([]string{
		"foo", "bar", "foobar", "barfoo", "ab", "aab", "abb", "xabx", "",
		"123", "0", "curl", "CURL", "Curl", "libssl.so.3", "libssl.so", "openssl-dev",
		"dev", "-dev", "rf-x", "rf",
	}, searchRulePatternSubjects...)
}

// TestPatternShape_NeverRejectsAMatch is the property the whole prefilter rests on: a shape may only
// reject subjects the regex would have rejected too. A false negative here would silently stop a
// search rule from firing.
func TestPatternShape_NeverRejectsAMatch(t *testing.T) {
	patterns := []string{
		// every pattern the built-in rule set uses
		`.*\.rf(?:[._~-].*)?`,
		rapidfortDpkgRebuildMarker,
		`.*?\.fc(\d+)(?:[._~-].*)?`,
		`rf-.*`,
		`.*\.el\d+(?:[._~-].*)?`,
		`.*[.-]echo.*`,
		// and shapes the built-ins do not exercise
		`curl`,
		`(curl)`,
		`foo|bar`,
		`(?i)CURL`,
		`.*`,
		`\d+`,
		`rf-(.+)`,
		`.*-dev`,
		`lib.*\.so\.\d+`,
	}

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			anchored := anchorPattern(pattern)
			re := regexp.MustCompile(anchored)
			shape := newPatternShape(anchored)

			var matched int
			for _, subject := range patternShapeSubjects() {
				if re.MatchString(subject) {
					matched++
					require.Truef(t, shape.possible(subject),
						"shape %+v rejected %q, which the pattern matches", shape, subject)
				}
				// matchPattern must agree with the regex either way: the shape is an optimization,
				// never a change in meaning
				assert.Equalf(t, re.MatchString(subject), matchPattern(re, shape, subject),
					"matchPattern disagreed with the regex on %q", subject)
			}
			assert.NotZerof(t, matched, "no subject in the corpus matched %q", pattern)
		})
	}
}
