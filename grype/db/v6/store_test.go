package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreClose(t *testing.T) {
	t.Run("readonly mode does nothing", func(t *testing.T) {
		s := setupTestStore(t)
		s.empty = false
		s.writable = false

		err := s.Close()
		require.NoError(t, err)

		// the blob_digests table should still exist
		var exists int
		s.db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'blob_digests'").Scan(&exists)
		assert.Equal(t, 1, exists)

		// ensure we have our indexes
		var indexes []string
		s.db.Raw(`SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_autoindex%'`).Scan(&indexes)
		assert.NotEmpty(t, indexes)

	})

	t.Run("successful close in writable mode", func(t *testing.T) {
		s := setupTestStore(t)

		// ensure we have indexes to start with
		var indexes []string
		s.db.Raw(`SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_autoindex%'`).Scan(&indexes)
		assert.NotEmpty(t, indexes)

		err := s.Close()
		require.NoError(t, err)

		// ensure the digests table was dropped
		var exists int
		s.db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'blob_digests'").Scan(&exists)
		assert.Equal(t, 0, exists)

		// ensure all of our indexes were dropped
		indexes = nil
		s.db.Raw(`SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_autoindex%'`).Scan(&indexes)
		assert.Empty(t, indexes)
	})
}
