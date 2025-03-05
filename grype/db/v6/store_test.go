package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreClose(t *testing.T) {

	t.Run("readonly mode does nothing", func(t *testing.T) {
		dir := t.TempDir()
		s := setupTestStore(t, dir)
		s.empty = false
		s.writable = false

		err := s.Close()
		require.NoError(t, err)

		// ensure the connection is no longer open
		var indexes []string
		s.db.Raw(`SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_autoindex%'`).Scan(&indexes)
		assert.Empty(t, indexes)

		// get a new connection (readonly)
		s = setupReadOnlyTestStore(t, dir)

		// ensure we have our indexes
		indexes = nil
		s.db.Raw(`SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_autoindex%'`).Scan(&indexes)
		assert.NotEmpty(t, indexes)

	})

	t.Run("successful close in writable mode", func(t *testing.T) {
		dir := t.TempDir()
		s := setupTestStore(t, dir)

		// ensure we have indexes to start with
		var indexes []string
		s.db.Raw(`SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_autoindex%'`).Scan(&indexes)
		assert.NotEmpty(t, indexes)

		err := s.Close()
		require.NoError(t, err)

		// get a new connection (readonly)
		s = setupReadOnlyTestStore(t, dir)

		// ensure all of our indexes were dropped
		indexes = nil
		s.db.Raw(`SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_autoindex%'`).Scan(&indexes)
		assert.Empty(t, indexes)
	})
}
