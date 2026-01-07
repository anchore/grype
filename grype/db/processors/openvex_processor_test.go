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

func mockOpenVEXProcessorTransform(vulnerability unmarshal.OpenVEXVulnerability, _ provider.State) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            vulnerability,
		},
	}, nil
}

func TestV2OpenVEXProcessor_Process(t *testing.T) {
	f, err := os.Open("test-fixtures/openvex.json")
	require.NoError(t, err)
	defer tests.CloseFile(f)

	processor := NewV2OpenVEXProcessor(mockOpenVEXProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "openvex",
	})

	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestOpenVEXProcessor_IsSupported(t *testing.T) {
	tests := []struct {
		name      string
		schemaURL string
		want      bool
	}{
		{
			name:      "one actually used by vunnel is supported",
			schemaURL: "https://github.com/openvex/spec/openvex_json_schema_0.2.0.json",
			want:      true,
		},
		{
			name:      "openvex schema 0.2.1 is supported",
			schemaURL: "https://github.com/openvex/spec/openvex_json_schema_0.2.1.json",
			want:      true,
		},
		{
			name:      "openvex schema 0.3.1 is supported",
			schemaURL: "https://github.com/openvex/spec/openvex_json_schema_0.3.1.json",
			want:      true,
		},
		{
			name:      "openvex schema 0.1.1 is not supported",
			schemaURL: "https://github.com/openvex/spec/openvex_json_schema_0.1.1.json",
			want:      false,
		},
		{
			name:      "higher schema is not supported",
			schemaURL: "https://github.com/openvex/spec/openvex_json_schema_1.2.0.json",
			want:      false,
		},
		{
			name:      "non-openvex schema is not supported",
			schemaURL: "https://example.com/nvd/schema-1.4.0.json",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewV2OpenVEXProcessor(mockOpenVEXProcessorTransform)
			assert.Equal(t, tt.want, p.IsSupported(tt.schemaURL))
		})
	}
}
