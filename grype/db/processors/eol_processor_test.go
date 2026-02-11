package processors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
)

func mockEOLProcessorTransform(entry unmarshal.EndOfLifeDateRelease, state provider.State) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            entry,
		},
	}, nil
}

func TestEOLProcessor_Process(t *testing.T) {
	f, err := os.Open("test-fixtures/eol.json")
	require.NoError(t, err)
	defer f.Close()

	processor := NewV2EOLProcessor(mockEOLProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "eol",
	})

	assert.NoError(t, err)
	assert.Len(t, entries, 2)

	// Verify first entry is ubuntu
	entry0, ok := entries[0].Data.(unmarshal.EndOfLifeDateRelease)
	require.True(t, ok)
	assert.Equal(t, "ubuntu", entry0.Product)
	assert.Equal(t, "22.04", entry0.Name)
	assert.True(t, entry0.IsLTS)

	// Verify second entry is debian
	entry1, ok := entries[1].Data.(unmarshal.EndOfLifeDateRelease)
	require.True(t, ok)
	assert.Equal(t, "debian", entry1.Product)
	assert.Equal(t, "11", entry1.Name)
}

func TestEOLProcessor_Process_EmptyEntry(t *testing.T) {
	// Test that empty entries (product == "") are filtered out
	f, err := os.Open("test-fixtures/eol-with-empty.json")
	require.NoError(t, err)
	defer f.Close()

	processor := NewV2EOLProcessor(mockEOLProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "eol",
	})

	assert.NoError(t, err)
	// Should only have 1 entry (empty one filtered out)
	assert.Len(t, entries, 1)
	entry, ok := entries[0].Data.(unmarshal.EndOfLifeDateRelease)
	require.True(t, ok)
	assert.Equal(t, "alpine", entry.Product)
}

func TestEOLProcessor_IsSupported(t *testing.T) {
	tc := []struct {
		name      string
		schemaURL string
		expected  bool
	}{
		{
			name:      "valid schema URL with version 1.0.0",
			schemaURL: "https://example.com/vunnel/path/eol/schema-1.0.0.json",
			expected:  true,
		},
		{
			name:      "valid schema URL with version 1.2.3",
			schemaURL: "https://example.com/vunnel/path/eol/schema-1.2.3.json",
			expected:  true,
		},
		{
			name:      "invalid schema URL with unsupported version",
			schemaURL: "https://example.com/vunnel/path/eol/schema-2.0.0.json",
			expected:  false,
		},
		{
			name:      "invalid schema URL with missing version",
			schemaURL: "https://example.com/vunnel/path/eol/schema.json",
			expected:  false,
		},
		{
			name:      "completely invalid URL",
			schemaURL: "https://example.com/invalid/schema/url",
			expected:  false,
		},
		{
			name:      "invalid schema segment",
			schemaURL: "https://example.com/vunnel/path/not-eol/schema-1.0.0.json",
			expected:  false,
		},
		{
			name:      "epss schema should not match",
			schemaURL: "https://example.com/vunnel/path/epss/schema-1.0.0.json",
			expected:  false,
		},
	}

	p := eolProcessor{}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.IsSupported(tt.schemaURL))
		})
	}
}
