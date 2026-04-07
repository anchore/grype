package processors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/testutil"
	"github.com/anchore/grype/grype/db/provider"
)

func mockCSAFVEXProcessorTransform(advisory unmarshal.CSAFVEXAdvisory, state provider.State) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            advisory,
		},
	}, nil
}

func TestV2CSAFVEXProcessor_Process(t *testing.T) {
	f, err := os.Open("testdata/csaf-vex.json")
	require.NoError(t, err)
	defer testutil.CloseFile(f)

	processor := NewV2CSAFVEXProcessor(mockCSAFVEXProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "hummingbird",
	})

	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestCSAFVEXProcessor_IsSupported(t *testing.T) {
	tests := []struct {
		name      string
		schemaURL string
		want      bool
	}{
		{
			name:      "csaf-vex schema 2.0.0 is supported",
			schemaURL: "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/csaf-vex/schema-2.0.0.json",
			want:      true,
		},
		{
			name:      "csaf-vex schema 2.1.0 is supported",
			schemaURL: "https://example.com/csaf-vex/schema-2.1.0.json",
			want:      true,
		},
		{
			name:      "csaf-vex schema 1.0.0 is not supported",
			schemaURL: "https://example.com/csaf-vex/schema-1.0.0.json",
			want:      false,
		},
		{
			name:      "csaf-vex schema 3.0.0 is not supported",
			schemaURL: "https://example.com/csaf-vex/schema-3.0.0.json",
			want:      false,
		},
		{
			name:      "non-csaf-vex schema is not supported",
			schemaURL: "https://example.com/osv/schema-2.0.0.json",
			want:      false,
		},
		{
			name:      "openvex schema is not matched",
			schemaURL: "https://example.com/openvex/schema-2.0.0.json",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewV2CSAFVEXProcessor(mockCSAFVEXProcessorTransform)
			assert.Equal(t, tt.want, p.IsSupported(tt.schemaURL))
		})
	}
}
