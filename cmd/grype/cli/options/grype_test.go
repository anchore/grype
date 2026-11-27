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

func TestGrype_PostLoad_distro(t *testing.T) {
	tests := []struct {
		name    string
		distro  string
		wantErr require.ErrorAssertionFunc
	}{
		{name: "empty is allowed", distro: "", wantErr: require.NoError},
		{name: "known distro", distro: "debian-11", wantErr: require.NoError},
		{name: "known distro alias", distro: "amzn-2", wantErr: require.NoError},
		{name: "typo is rejected", distro: "debin-11", wantErr: require.Error},
		{name: "unknown distro is rejected", distro: "notadistro", wantErr: require.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			o := Grype{Distro: tt.distro}
			tt.wantErr(t, o.PostLoad())
		})
	}
}
