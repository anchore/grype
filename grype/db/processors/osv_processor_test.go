package processors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/tests"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/unmarshal"
)

func mockOSVProcessorTransform(vulnerability unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            vulnerability,
		},
	}, nil
}

func TestV2OSVProcessor_Process(t *testing.T) {
	f, err := os.Open("test-fixtures/osv.json")
	require.NoError(t, err)
	defer tests.CloseFile(f)

	processor := NewV2OSVProcessor(mockOSVProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "osv",
	})

	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestOSVProcessor_IsSupported(t *testing.T) {
	tests := []struct {
		name      string
		schemaURL string
		want      bool
	}{
		{
			name:      "one actually used by vunnel is supported",
			schemaURL: "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/osv/schema-1.5.0.json",
			want:      true,
		},
		{
			name:      "osv schema 1.6.1 is supported",
			schemaURL: "https://example.com/osv/schema-1.6.1.json",
			want:      true,
		},
		{
			name:      "osv schema 1.5.0 is supported",
			schemaURL: "https://example.com/osv/schema-1.5.0.json",
			want:      true,
		},
		{
			name:      "lower major version is not supported",
			schemaURL: "https://example.com/osv/schema-0.4.0.json",
			want:      false,
		},
		{
			name:      "higher schema is not supported",
			schemaURL: "https://example.com/osv/schema-2.4.0.json",
			want:      false,
		},
		{
			name:      "non-osv schema is not supported",
			schemaURL: "https://example.com/nvd/schema-1.4.0.json",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewV2OSVProcessor(mockOSVProcessorTransform)
			assert.Equal(t, tt.want, p.IsSupported(tt.schemaURL))
		})
	}
}
