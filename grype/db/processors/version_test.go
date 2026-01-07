package processors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name      string
		schemaURL string
		expected  *version
		wantErr   bool
	}{
		{
			name:      "valid version 1.0.0",
			schemaURL: "https://example.com/vunnel/path/schema-1.0.0.json",
			expected:  &version{Major: 1, Minor: 0, Patch: 0},
			wantErr:   false,
		},
		{
			name:      "valid version 2.3.4",
			schemaURL: "https://example.com/vunnel/path/schema-2.3.4.json",
			expected:  &version{Major: 2, Minor: 3, Patch: 4},
			wantErr:   false,
		},
		{
			name:      "missing patch version",
			schemaURL: "https://example.com/vunnel/path/schema-1.0.json",
			expected:  nil,
			wantErr:   true,
		},
		{
			name:      "invalid format",
			schemaURL: "https://example.com/vunnel/path/schema.json",
			expected:  nil,
			wantErr:   true,
		},
		{
			name:      "non-numeric version",
			schemaURL: "https://example.com/vunnel/path/schema-1.a.0.json",
			expected:  nil,
			wantErr:   true,
		},
		{
			name:      "valid version with extra path",
			schemaURL: "https://example.com/vunnel/path/vulnerability/schema_1.2.3.json",
			expected:  &version{Major: 1, Minor: 2, Patch: 3},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseVersion(tt.schemaURL)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
