package v6

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg/qualifier/architecture"
)

func TestArchitectureAliasStore_GetArchitectureAliases_SeededDefaults(t *testing.T) {
	// setupTestStore opens an empty+writable DB, which seeds InitialData (including the
	// architecture aliases). The read-back must equal the build-time default table.
	s := setupTestStore(t)

	got, err := s.GetArchitectureAliases()
	require.NoError(t, err)
	require.Equal(t, architecture.DefaultAliases(), got)
}

func TestArchitectureAliasStore_GetArchitectureAliases_MissingTableIsEmptyNotError(t *testing.T) {
	// a database built before the architecture_aliases table existed has no such table; that
	// must read as an empty map (the qualifier's signal to fall back to built-in defaults),
	// never an error.
	s := setupTestStore(t)
	require.NoError(t, s.db.Migrator().DropTable(&ArchitectureAlias{}))

	got, err := s.GetArchitectureAliases()
	require.NoError(t, err)
	require.Empty(t, got)
}
