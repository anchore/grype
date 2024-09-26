package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestDbMetadataStore_empty(t *testing.T) {
	s := newDBMetadataStore(setupTestDB(t))

	// attempt to fetch a non-existent record
	actualMetadata, err := s.GetDBMetadata()
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	require.NotNil(t, actualMetadata)
}

func TestDbMetadataStore(t *testing.T) {
	s := newDBMetadataStore(setupTestDB(t))

	require.NoError(t, s.SetDBMetadata())

	// fetch the record
	actualMetadata, err := s.GetDBMetadata()
	require.NoError(t, err)
	require.NotNil(t, actualMetadata)

	assert.NotZero(t, *actualMetadata.BuildTimestamp) // a timestamp was set
	name, _ := actualMetadata.BuildTimestamp.Zone()
	assert.Equal(t, "UTC", name) // the timestamp is in UTC

	actualMetadata.BuildTimestamp = nil // value not under test

	assert.Equal(t, DBMetadata{
		BuildTimestamp: nil,
		// expect the correct version info
		Model:    ModelVersion,
		Revision: Revision,
		Addition: Addition,
	}, *actualMetadata)
}

func setupTestDB(t *testing.T) *gorm.DB {
	// note: empty path means in-memory db
	s, err := newStore(Config{}, true)
	require.NoError(t, err)

	return s.db
}
