package v6

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSearchRuleStore_SeededDefaults(t *testing.T) {
	// setupTestStore opens an empty+writable DB, which seeds InitialData (including the search
	// rules). The read-back must equal the build-time default rule set.
	s := setupTestStore(t)

	got, err := s.GetSearchRules()
	require.NoError(t, err)

	require.Equal(t, KnownSearchRules(), got)
}

func TestSearchRuleStore_MissingTableIsNilNotError(t *testing.T) {
	// a database built before the search_rules table existed has no such table; that must
	// read as nil (the provider's signal to fall back to built-in defaults), never an error.
	s := setupTestStore(t)
	require.NoError(t, s.db.Migrator().DropTable(&SearchRule{}))

	got, err := s.GetSearchRules()
	require.NoError(t, err)
	require.Nil(t, got)
}
