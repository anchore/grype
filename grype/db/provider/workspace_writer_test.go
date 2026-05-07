package provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceWriter_WriteState(t *testing.T) {
	tmpDir := t.TempDir()
	writer := NewWorkspaceWriter(tmpDir, "test-provider")

	state := State{
		Provider:  "test-provider",
		Version:   1,
		Processor: "vunnel@1.0.0",
		Schema: Schema{
			Version: "1.0.0",
			URL:     "https://example.com/schema.json",
		},
		Timestamp: time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
		Listing: &File{
			Path:      "results/listing.xxh64",
			Algorithm: "xxh64",
		},
		Store: "flat-file",
	}

	err := writer.WriteState(state)
	require.NoError(t, err)

	// verify file was created
	statePath := filepath.Join(tmpDir, "test-provider", "metadata.json")
	data, err := os.ReadFile(statePath)
	require.NoError(t, err)

	// verify JSON structure
	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "test-provider", parsed["provider"])
	assert.Equal(t, float64(1), parsed["version"])
	assert.Equal(t, "vunnel@1.0.0", parsed["processor"])
	assert.Equal(t, "flat-file", parsed["store"])
	assert.Equal(t, "2024-01-15T12:00:00Z", parsed["timestamp"])

	schema := parsed["schema"].(map[string]any)
	assert.Equal(t, "1.0.0", schema["version"])
	assert.Equal(t, "https://example.com/schema.json", schema["url"])

	listing := parsed["listing"].(map[string]any)
	assert.Equal(t, "results/listing.xxh64", listing["path"])
	assert.Equal(t, "xxh64", listing["algorithm"])
}

func TestWorkspaceWriter_WriteResult(t *testing.T) {
	tmpDir := t.TempDir()
	writer := NewWorkspaceWriter(tmpDir, "test-provider")

	content := []byte(`{"identifier": "debian:10/CVE-2024-1234", "item": {}}`)
	file, err := writer.WriteResult("CVE-2024-1234.json", content)
	require.NoError(t, err)

	// verify file entry
	assert.Equal(t, "results/CVE-2024-1234.json", file.Path)
	assert.Equal(t, "xxh64", file.Algorithm)
	assert.NotEmpty(t, file.Digest)

	// verify file was created with pretty-formatted JSON
	resultPath := filepath.Join(tmpDir, "test-provider", "results", "CVE-2024-1234.json")
	data, err := os.ReadFile(resultPath)
	require.NoError(t, err)

	expectedFormatted := `{
  "identifier": "debian:10/CVE-2024-1234",
  "item": {}
}
`
	assert.Equal(t, expectedFormatted, string(data))
}

func TestWorkspaceWriter_CopyResultFrom(t *testing.T) {
	tmpDir := t.TempDir()

	// create source file
	sourceDir := filepath.Join(tmpDir, "source")
	err := os.MkdirAll(sourceDir, 0755)
	require.NoError(t, err)

	sourcePath := filepath.Join(sourceDir, "CVE-2024-5678.json")
	content := []byte(`{"identifier": "debian:11/CVE-2024-5678", "item": {}}`)
	err = os.WriteFile(sourcePath, content, 0644)
	require.NoError(t, err)

	// copy to workspace
	writer := NewWorkspaceWriter(tmpDir, "test-provider")
	file, err := writer.CopyResultFrom(sourcePath)
	require.NoError(t, err)

	// verify file entry
	assert.Equal(t, "results/CVE-2024-5678.json", file.Path)
	assert.NotEmpty(t, file.Digest)

	// verify file was copied with pretty-formatted JSON
	destPath := filepath.Join(tmpDir, "test-provider", "results", "CVE-2024-5678.json")
	data, err := os.ReadFile(destPath)
	require.NoError(t, err)

	expectedFormatted := `{
  "identifier": "debian:11/CVE-2024-5678",
  "item": {}
}
`
	assert.Equal(t, expectedFormatted, string(data))
}

func TestWorkspaceWriter_WriteListing(t *testing.T) {
	tmpDir := t.TempDir()
	writer := NewWorkspaceWriter(tmpDir, "test-provider")

	files := []File{
		{Path: "results/CVE-2024-0002.json", Digest: "bbbbbbbbbbbbbbbb", Algorithm: "xxh64"},
		{Path: "results/CVE-2024-0001.json", Digest: "aaaaaaaaaaaaaaaa", Algorithm: "xxh64"},
	}

	err := writer.WriteListing(files)
	require.NoError(t, err)

	// verify listing file
	listingPath := filepath.Join(tmpDir, "test-provider", "results", "listing.xxh64")
	data, err := os.ReadFile(listingPath)
	require.NoError(t, err)

	// should be sorted by path
	expected := "aaaaaaaaaaaaaaaa  results/CVE-2024-0001.json\nbbbbbbbbbbbbbbbb  results/CVE-2024-0002.json\n"
	assert.Equal(t, expected, string(data))
}

func TestWorkspaceWriter_RoundTrip(t *testing.T) {
	// test that a workspace written by WorkspaceWriter can be read by ReadState
	tmpDir := t.TempDir()
	writer := NewWorkspaceWriter(tmpDir, "roundtrip-provider")

	// write a result
	content := []byte(`{"identifier": "debian:10/CVE-2024-1234", "item": {"test": true}}`)
	file, err := writer.WriteResult("CVE-2024-1234.json", content)
	require.NoError(t, err)

	// write listing
	err = writer.WriteListing([]File{*file})
	require.NoError(t, err)

	// write state
	state := State{
		Provider:  "roundtrip-provider",
		Version:   1,
		Processor: "test",
		Schema: Schema{
			Version: "1.0.0",
			URL:     "https://example.com/schema.json",
		},
		Timestamp: time.Date(2024, 6, 1, 10, 30, 0, 0, time.UTC),
		Listing: &File{
			Path:      "results/listing.xxh64",
			Algorithm: "xxh64",
		},
		Store: "flat-file",
	}
	err = writer.WriteState(state)
	require.NoError(t, err)

	// now read it back using ReadState
	statePath := filepath.Join(tmpDir, "roundtrip-provider", "metadata.json")
	readState, err := ReadState(statePath)
	require.NoError(t, err)

	// verify state fields
	assert.Equal(t, "roundtrip-provider", readState.Provider)
	assert.Equal(t, 1, readState.Version)
	assert.Equal(t, "test", readState.Processor)
	assert.Equal(t, "1.0.0", readState.Schema.Version)
	assert.Equal(t, "flat-file", readState.Store)

	// verify result paths
	paths := readState.ResultPaths()
	require.Len(t, paths, 1)
	assert.Contains(t, paths[0], "CVE-2024-1234.json")
}
