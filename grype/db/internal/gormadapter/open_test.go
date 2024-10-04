package gormadapter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigApply(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		options        []Option
		expectedPath   string
		expectedMemory bool
	}{
		{
			name:           "apply with path",
			path:           "test.db",
			options:        []Option{},
			expectedPath:   "test.db",
			expectedMemory: false,
		},
		{
			name:           "apply with empty path (memory)",
			path:           "",
			options:        []Option{},
			expectedPath:   "",
			expectedMemory: true,
		},
		{
			name:           "apply with truncate option",
			path:           "test.db",
			options:        []Option{WithTruncate(true)},
			expectedPath:   "test.db",
			expectedMemory: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newConfig(tt.path, tt.options)

			require.Equal(t, tt.expectedPath, c.path)
			require.Equal(t, tt.expectedMemory, c.memory)
		})
	}
}

func TestConfigShouldTruncate(t *testing.T) {
	tests := []struct {
		name             string
		write            bool
		memory           bool
		expectedTruncate bool
	}{
		{
			name:             "should truncate when write is true and not memory",
			write:            true,
			memory:           false,
			expectedTruncate: true,
		},
		{
			name:             "should not truncate when write is false",
			write:            false,
			memory:           false,
			expectedTruncate: false,
		},
		{
			name:             "should not truncate when using in-memory DB",
			write:            true,
			memory:           true,
			expectedTruncate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := config{
				write:  tt.write,
				memory: tt.memory,
			}
			require.Equal(t, tt.expectedTruncate, c.shouldTruncate())
		})
	}
}

func TestConfigConnectionString(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		write           bool
		memory          bool
		expectedConnStr string
	}{
		{
			name:            "writable path",
			path:            "test.db",
			write:           true,
			expectedConnStr: "file:test.db?cache=shared",
		},
		{
			name:            "read-only path",
			path:            "test.db",
			write:           false,
			expectedConnStr: "file:test.db?cache=shared&immutable=1&cache=shared&mode=ro",
		},
		{
			name:            "in-memory mode",
			path:            "",
			write:           false,
			memory:          true,
			expectedConnStr: ":memory:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := config{
				path:   tt.path,
				write:  tt.write,
				memory: tt.memory,
			}
			require.Equal(t, tt.expectedConnStr, c.connectionString())
		})
	}
}
