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

func Test_configFilesFromCWD(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		expected []string
	}{
		{
			name:     "empty",
			config:   "",
			expected: nil,
		},
		{
			name:     "cwd flat config",
			config:   ".grype.yaml",
			expected: []string{".grype.yaml"},
		},
		{
			name:     "explicit relative cwd path is preserved",
			config:   "./.grype.yaml",
			expected: []string{"./.grype.yaml"},
		},
		{
			name:     "appname subdir is not flagged as cwd",
			config:   ".grype/config.yaml",
			expected: nil,
		},
		{
			name:     "home dir config is not flagged",
			config:   "/home/user/.grype.yaml",
			expected: nil,
		},
		{
			name:     "mixed list only returns cwd entries",
			config:   ".grype.yaml,/home/user/.grype.yaml",
			expected: []string{".grype.yaml"},
		},
		{
			name:     "whitespace is trimmed",
			config:   " .grype.yaml , /etc/grype.yaml ",
			expected: []string{".grype.yaml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := configFilesFromCWD(tt.config)
			assert.Equal(t, tt.expected, got)
		})
	}
}
