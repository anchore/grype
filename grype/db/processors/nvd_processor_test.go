package processors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/tests"
	"github.com/anchore/grype/grype/db/provider"
)

func mockNVDProcessorTransform(vulnerability unmarshal.NVDVulnerability) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            vulnerability,
		},
	}, nil
}

func TestNVDProcessor_Process(t *testing.T) {
	f, err := os.Open("test-fixtures/nvd.json")
	require.NoError(t, err)
	defer tests.CloseFile(f)

	processor := NewNVDProcessor(mockNVDProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "nvd",
	})

	require.NoError(t, err)
	assert.Len(t, entries, 3)
}

func TestNvdProcessor_IsSupported(t *testing.T) {
	tc := []struct {
		name      string
		schemaURL string
		expected  bool
	}{
		{
			name:      "valid schema URL with version 1.0.0",
			schemaURL: "https://example.com/vunnel/path/vulnerability/nvd/schema-1.0.0.json",
			expected:  true,
		},
		{
			name:      "valid schema URL with version 1.4.7",
			schemaURL: "https://example.com/vunnel/path/vulnerability/nvd/schema-1.4.7.json",
			expected:  true,
		},
		{
			name:      "invalid schema URL with unsupported version",
			schemaURL: "https://example.com/vunnel/path/vulnerability/nvd/schema-2.0.0.json",
			expected:  false,
		},
		{
			name:      "invalid schema URL with missing version",
			schemaURL: "https://example.com/vunnel/path/vulnerability/nvd/schema.json",
			expected:  false,
		},
		{
			name:      "completely invalid URL",
			schemaURL: "https://example.com/invalid/schema/url",
			expected:  false,
		},
	}

	p := nvdProcessor{}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.IsSupported(tt.schemaURL))
		})
	}
}
