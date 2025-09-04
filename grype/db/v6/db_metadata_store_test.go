package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestDbMetadataStore_empty(t *testing.T) {
	db := setupTestStore(t).db
	require.NoError(t, db.Where("true").Delete(&DBMetadata{}).Error) // delete all existing records
	s := newDBMetadataStore(db)

	// attempt to fetch a non-existent record
	actualMetadata, err := s.GetDBMetadata()
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	require.NotNil(t, actualMetadata)
}

func TestDbMetadataStore_oldDb(t *testing.T) {
	db := setupTestStore(t).db
	require.NoError(t, db.Where("true").Model(DBMetadata{}).Update("Model", "5").Error) // old database version
	s := newDBMetadataStore(db)

	// attempt to fetch a non-existent record
	actualMetadata, err := s.GetDBMetadata()
	require.NoError(t, err)
	require.NotNil(t, actualMetadata)
}

func TestDbMetadataStore(t *testing.T) {
	s := newDBMetadataStore(setupTestStore(t).db)

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

func setupTestStore(t testing.TB, d ...string) *store {
	var dir string
	switch len(d) {
	case 0:
		dir = t.TempDir()
	case 1:
		dir = d[0]
	default:
		t.Fatal("too many arguments")

	}

	s, err := newStore(Config{
		DBDirPath: dir,
	}, true, true)
	require.NoError(t, err)

	require.NoError(t, s.SetDBMetadata())

	// Populate test data for grype's matching behavior tests
	// In production, this data is managed by grype-db during database construction
	require.NoError(t, populateTestOverridesForMatchingTests(s))

	return s
}

// populateTestOverridesForMatchingTests populates OS and package aliases solely for testing
// grype's override matching behavior. In production, this data is managed by grype-db.
func populateTestOverridesForMatchingTests(s *store) error {
	// Populate OS specifier overrides for testing grype's matching logic
	osOverrides := testOperatingSystemSpecifierOverrides()
	for i := range osOverrides {
		override := &osOverrides[i]
		if err := s.db.Create(override).Error; err != nil {
			return err
		}
	}

	// Populate package specifier overrides for testing grype's matching logic
	packageOverrides := testPackageSpecifierOverrides()
	for i := range packageOverrides {
		override := &packageOverrides[i]
		if err := s.db.Create(override).Error; err != nil {
			return err
		}
	}

	return nil
}

func setupReadOnlyTestStore(t testing.TB, dir string) *store {
	s, err := newStore(Config{
		DBDirPath: dir,
	}, false, false)
	require.NoError(t, err)

	return s
}
