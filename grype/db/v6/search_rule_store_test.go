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

func TestSearchRuleStore_MissingTableIsNilNotError(t *testing.T) {
	// a DB built before the table existed reads as nil, not an error
	s := setupTestStore(t)
	require.NoError(t, s.db.Migrator().DropTable(&SearchRule{}))

	got, err := s.GetSearchRules()
	require.NoError(t, err)
	require.Nil(t, got)
}
