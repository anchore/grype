package v6

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestSearchRuleStore_SeededDefaults(t *testing.T) {
	// an empty writable store seeds InitialData, including KnownSearchRules
	s := setupTestStore(t)

	require.Equal(t, KnownSearchRules(), s.GetSearchRules())
}

func TestNewVulnerabilityProvider_SearchRuleDefaults(t *testing.T) { //nolint:funlen // one case per load path
	custom := SearchRule{Action: SearchRuleReplace, MatchEcosystem: "custom", MatchPackageName: "pkg", ReplacementPackageName: "other"}
	other := SearchRule{Action: SearchRuleReplace, MatchEcosystem: "custom", MatchPackageName: "pkg", ReplacementPackageName: "another"}

	// writes the rules as the table's only rows, skipping BeforeCreate's validation so a row may be
	// one this client cannot use
	writeRules := func(t *testing.T, s *store, rules ...SearchRule) {
		t.Helper()
		require.NoError(t, s.db.Where("1 = 1").Delete(&SearchRule{}).Error)
		if len(rules) > 0 {
			require.NoError(t, s.db.Session(&gorm.Session{SkipHooks: true}).Create(rules).Error)
		}
	}

	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  []SearchRule
	}{
		{
			name: "seeded rules are used",
			setup: func(t *testing.T, dir string) {
				setupTestStore(t, dir)
			},
			want: KnownSearchRules(),
		},
		{
			name: "the table's rules are used as written, without the built-in rules",
			setup: func(t *testing.T, dir string) {
				writeRules(t, setupTestStore(t, dir), custom)
			},
			want: []SearchRule{custom},
		},
		{
			// read order breaks priority ties
			name: "rules are read in table order",
			setup: func(t *testing.T, dir string) {
				writeRules(t, setupTestStore(t, dir), other, custom)
			},
			want: []SearchRule{other, custom},
		},
		{
			name: "an empty table applies no rules",
			setup: func(t *testing.T, dir string) {
				writeRules(t, setupTestStore(t, dir))
			},
			want: nil,
		},
		{
			// e.g. rows with no action, or with an action a newer DB introduced
			name: "a table whose every rule is unusable applies no rules",
			setup: func(t *testing.T, dir string) {
				noAction := KnownSearchRules()[0]
				noAction.Action = ""
				futureAction := KnownSearchRules()[0]
				futureAction.Action = "some-future-action"
				writeRules(t, setupTestStore(t, dir), noAction, futureAction)
			},
			want: nil,
		},
		{
			name: "a rule with a malformed client schema constraint is skipped",
			setup: func(t *testing.T, dir string) {
				bad := other
				bad.ApplicableClientDBSchemas = "not-a-constraint"
				writeRules(t, setupTestStore(t, dir), bad, custom)
			},
			want: []SearchRule{custom},
		},
		{
			name: "missing table falls back to defaults",
			setup: func(t *testing.T, dir string) {
				s := setupTestStore(t, dir)
				require.NoError(t, s.db.Migrator().DropTable(&SearchRule{}))
			},
			want: KnownSearchRules(),
		},
		{
			// hydrating a DB built before the table existed creates it empty
			name: "hydrated DB predating the table falls back to defaults",
			setup: func(t *testing.T, dir string) {
				s := setupTestStore(t, dir)
				require.NoError(t, s.db.Migrator().DropTable(&SearchRule{}))
				require.NoError(t, s.db.Model(&DBMetadata{}).Where("true").Update("addition", searchRulesIntroduced.Addition-1).Error)
				require.NoError(t, s.Close())
				require.NoError(t, Hydrater()(dir))
			},
			want: KnownSearchRules(),
		},
		{
			name: "a read error falls back to defaults",
			setup: func(t *testing.T, dir string) {
				s := setupTestStore(t, dir)
				writeRules(t, s, custom)
				require.NoError(t, s.db.Exec("UPDATE search_rules SET priority = 'not-a-number'").Error)
			},
			want: KnownSearchRules(),
		},
		{
			// a newer DB may narrow a rule by a column this client does not know, which it must not apply
			// more broadly than written
			name: "rules setting an unknown column are skipped",
			setup: func(t *testing.T, dir string) {
				s := setupTestStore(t, dir)
				narrowed := other
				narrowed.ReplacementPackageName = "narrowed"
				writeRules(t, s, narrowed, other, custom)
				require.NoError(t, s.db.Exec("ALTER TABLE search_rules ADD COLUMN match_future TEXT").Error)
				require.NoError(t, s.db.Exec("UPDATE search_rules SET match_future = 'x' WHERE replacement_package_name = 'narrowed'").Error)
				require.NoError(t, s.db.Exec("UPDATE search_rules SET match_future = '' WHERE replacement_package_name = 'another'").Error)
			},
			want: []SearchRule{other, custom},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(t, dir)

			p := NewVulnerabilityProvider(setupReadOnlyTestStore(t, dir)).(*vulnerabilityProvider)
			require.Equal(t, newSearchIndex(tt.want), p.searchRules)
		})
	}
}

// A pattern is DB text: one that fails to compile, or that breaks out of the anchoring group, skips its
// row with a warning rather than crashing the scan or applying more broadly than written.
func TestSearchRuleStore_SkipsBadPatterns(t *testing.T) {
	tooLargeFolded := tooLargeWhenFolded(t)
	tests := []struct {
		name    string
		pattern string
	}{
		{name: "too large once case folded", pattern: tooLargeFolded},
		{name: "escapes the anchoring group", pattern: `a)|(?:b`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnedSearchRules.Clear()
			logs := recordDebugLogs(t)

			s := setupTestStore(t)
			good := SearchRule{Action: SearchRuleDrop, MatchEcosystem: "custom", MatchPackageName: "pkg"}
			bad := SearchRule{Action: SearchRuleDrop, MatchEcosystem: "custom", MatchPackageName: tt.pattern}
			require.NoError(t, s.db.Where("1 = 1").Delete(&SearchRule{}).Error)
			require.NoError(t, s.db.Session(&gorm.Session{SkipHooks: true}).Create([]SearchRule{bad, good}).Error)

			require.Equal(t, []SearchRule{good}, s.GetSearchRules())

			require.Len(t, *logs, 1)
			assert.Equal(t, "skipping search rule this grype version cannot apply", (*logs)[0].msg)
			assert.Equal(t, "1", (*logs)[0].fields["rowid"])
			assert.Contains(t, (*logs)[0].fields["error"], "invalid pattern")
			assert.Less(t, len((*logs)[0].fields["error"]), 1000, "the pattern is abbreviated")

			// a second load does not warn again
			require.Equal(t, []SearchRule{good}, s.GetSearchRules())
			assert.Len(t, *logs, 1)
		})
	}
}

// tooLargeWhenFolded returns a pattern that compiles anchored but not case folded: a run of one class
// whose runes case folding adds to, long enough that only the folded run exceeds regexp's rune limit.
func tooLargeWhenFolded(t *testing.T) string {
	t.Helper()
	const class = `\p{Mn}`
	plain, err := syntax.Parse(class, syntax.Perl)
	require.NoError(t, err)
	folded, err := syntax.Parse(class, syntax.Perl|syntax.FoldCase)
	require.NoError(t, err)
	require.Greater(t, len(folded.Rune), len(plain.Rune), "case folding must add runes to the class")

	const maxRunes = 128 << 20 / 4 // regexp/syntax's limit on runes in classes
	pattern := strings.Repeat(class, maxRunes/len(folded.Rune)+1)

	_, err = regexp.Compile("^(?:" + pattern + ")$")
	require.NoError(t, err, "the pattern must compile without case folding")
	_, err = regexp.Compile("(?i)^(?:" + pattern + ")$")
	require.Error(t, err, "the pattern must fail to compile case folded")
	return pattern
}
