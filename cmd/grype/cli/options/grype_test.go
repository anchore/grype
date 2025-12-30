package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_flatten(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "single value",
			input:    []string{"docker"},
			expected: []string{"docker"},
		},
		{
			name:     "comma-separated values",
			input:    []string{"docker,registry"},
			expected: []string{"docker", "registry"},
		},
		{
			name:     "multiple entries with commas",
			input:    []string{"docker,registry", "podman"},
			expected: []string{"docker", "registry", "podman"}, // preserves order
		},
		{
			name:     "whitespace trimming",
			input:    []string{" docker , registry "},
			expected: []string{"docker", "registry"},
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := flatten(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestGrype_PostLoad_StdoutValidation(t *testing.T) {
	tests := []struct {
		name    string
		stdout  string
		wantErr string
	}{
		{
			name:    "valid stdout format table",
			stdout:  "table",
			wantErr: "",
		},
		{
			name:    "valid stdout format json",
			stdout:  "json",
			wantErr: "",
		},
		{
			name:    "valid stdout format sarif",
			stdout:  "sarif",
			wantErr: "",
		},
		{
			name:    "empty stdout format is valid",
			stdout:  "",
			wantErr: "",
		},
		{
			name:    "invalid stdout format",
			stdout:  "invalid-format",
			wantErr: "bad --stdout format value 'invalid-format'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Grype{
				Stdout: tt.stdout,
			}
			err := opts.PostLoad()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
