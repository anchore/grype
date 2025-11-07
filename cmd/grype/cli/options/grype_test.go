package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
