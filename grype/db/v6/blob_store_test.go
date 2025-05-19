package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlobWriter_AddBlobs(t *testing.T) {
	db := setupTestStore(t).db
	writer := newBlobStore(db)

	obj1 := map[string]string{"key": "value1"}
	obj2 := map[string]string{"key": "value2"}

	blob1 := newBlob(obj1)
	blob2 := newBlob(obj2)
	blob3 := newBlob(obj1) // same as blob1

	err := writer.addBlobs(blob1, blob2, blob3)
	require.NoError(t, err)

	require.NotZero(t, blob1.ID)
	require.Equal(t, blob1.ID, blob3.ID) // blob3 should have the same ID as blob1 (natural deduplication)

	var result1 Blob
	require.NoError(t, db.Where("id = ?", blob1.ID).First(&result1).Error)
	assert.Equal(t, blob1.Value, result1.Value)

	var result2 Blob
	require.NoError(t, db.Where("id = ?", blob2.ID).First(&result2).Error)
	assert.Equal(t, blob2.Value, result2.Value)
}

func TestBlob_computeDigest(t *testing.T) {
	assert.Equal(t, "xxh64:0e6882304e9adbd5", Blob{Value: "test content"}.computeDigest())

	assert.Equal(t, "xxh64:ea0c19ae9fbd93b3", Blob{Value: "different content"}.computeDigest())
}
