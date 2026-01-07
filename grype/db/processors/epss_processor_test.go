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

func mockEPSSProcessorTransform(entry unmarshal.EPSS, state provider.State) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            entry,
		},
	}, nil
}

func TestEPSSProcessor_Process(t *testing.T) {
	f, err := os.Open("test-fixtures/epss.json")
	require.NoError(t, err)
	defer f.Close()

	processor := NewV2EPSSProcessor(mockEPSSProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "epss",
	})

	assert.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestEPSSProcessor_IsSupported(t *testing.T) {
	tc := []struct {
		name      string
		schemaURL string
		expected  bool
	}{
		{
			name:      "valid schema URL with version 1.0.0",
			schemaURL: "https://example.com/vunnel/path/vulnerability/epss/schema-1.0.0.json",
			expected:  true,
		},
		{
			name:      "valid schema URL with version 1.2.3",
			schemaURL: "https://example.com/vunnel/path/vulnerability/epss/schema-1.2.3.json",
			expected:  true,
		},
		{
			name:      "invalid schema URL with unsupported version",
			schemaURL: "https://example.com/vunnel/path/vulnerability/epss/schema-2.0.0.json",
			expected:  false,
		},
		{
			name:      "invalid schema URL with missing version",
			schemaURL: "https://example.com/vunnel/path/vulnerability/epss/schema.json",
			expected:  false,
		},
		{
			name:      "completely invalid URL",
			schemaURL: "https://example.com/invalid/schema/url",
			expected:  false,
		},
		{
			name:      "invalid schema segment",
			schemaURL: "https://example.com/vunnel/path/vulnerability/not-epss/schema-1.0.0.json",
			expected:  false,
		},
	}

	p := epssProcessor{}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.IsSupported(tt.schemaURL))
		})
	}
}
