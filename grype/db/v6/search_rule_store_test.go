package v6

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSearchRuleStore_SeededDefaults(t *testing.T) {
	// an empty writable store seeds InitialData, including KnownSearchRules
	s := setupTestStore(t)

	got, err := s.GetSearchRules()
	require.NoError(t, err)

	require.Equal(t, KnownSearchRules(), got)
}

func TestNewVulnerabilityProvider_SearchRuleDefaults(t *testing.T) {
	custom := SearchRule{MatchEcosystem: "custom", MatchPackageName: "pkg", Behavior: SearchRuleReplace, ReplacementPackageName: "other"}

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
