package v6

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestSearchRuleStore_SeededDefaults(t *testing.T) {
	// an empty writable store seeds InitialData, including KnownSearchRules
	s := setupTestStore(t)

	got, err := s.GetSearchRules()
	require.NoError(t, err)

	require.Equal(t, KnownSearchRules(), got)
}

func TestNewVulnerabilityProvider_SearchRuleDefaults(t *testing.T) {
	custom := SearchRule{Action: SearchRuleReplace, MatchEcosystem: "custom", MatchPackageName: "pkg", ReplacementPackageName: "other"}

	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  []SearchRule
	}{
		{
			name: "a single rule in the table prevents the defaults",
			setup: func(t *testing.T, dir string) {
				s := setupTestStore(t, dir)
				require.NoError(t, s.db.Where("1 = 1").Delete(&SearchRule{}).Error)
				require.NoError(t, s.db.Create(&custom).Error)
			},
			want: []SearchRule{custom},
		},
		{
			name: "empty table falls back to defaults",
			setup: func(t *testing.T, dir string) {
				s := setupTestStore(t, dir)
				require.NoError(t, s.db.Where("1 = 1").Delete(&SearchRule{}).Error)
			},
			want: KnownSearchRules(),
		},
		{
			// e.g. rows written before the action column existed, or with an action a newer DB
			// introduced: every row is skipped, so no rule would apply at all
			name: "a table whose every rule is unusable falls back to defaults",
			setup: func(t *testing.T, dir string) {
				s := setupTestStore(t, dir)
				require.NoError(t, s.db.Where("1 = 1").Delete(&SearchRule{}).Error)
				noAction := KnownSearchRules()[0]
				noAction.Action = ""
				futureAction := KnownSearchRules()[0]
				futureAction.Action = "some-future-action"
				// skip BeforeCreate's validation to write rows this client cannot use
				require.NoError(t, s.db.Session(&gorm.Session{SkipHooks: true}).Create([]SearchRule{noAction, futureAction}).Error)
			},
			want: KnownSearchRules(),
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
				require.NoError(t, s.Close())
				require.NoError(t, Hydrater()(dir))
			},
			want: KnownSearchRules(),
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
