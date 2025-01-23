package gormadapter

import (
	"os"
	"path/filepath"
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
			options:        []Option{WithTruncate(true, nil, nil)}, // migration and initial data don't matter
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
			expectedConnStr: "file:test.db?cache=shared&immutable=1&mode=ro&cache=shared",
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
				path:     tt.path,
				writable: tt.write,
				memory:   tt.memory,
			}
			require.Equal(t, tt.expectedConnStr, c.connectionString())
		})
	}
}

func TestPrepareWritableDB(t *testing.T) {

	t.Run("creates new directory and file when path does not exist", func(t *testing.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "newdir", "test.db")

		err := deleteDB(dbPath)
		require.NoError(t, err)

		_, err = os.Stat(filepath.Dir(dbPath))
		require.NoError(t, err)
	})

	t.Run("removes existing file at path", func(t *testing.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "test.db")

		_, err := os.Create(dbPath)
		require.NoError(t, err)

		_, err = os.Stat(dbPath)
		require.NoError(t, err)

		err = deleteDB(dbPath)
		require.NoError(t, err)

		_, err = os.Stat(dbPath)
		require.True(t, os.IsNotExist(err))
	})

	t.Run("returns error if unable to create parent directory", func(t *testing.T) {
		invalidDir := filepath.Join("/root", "invalidDir", "test.db")
		err := deleteDB(invalidDir)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to create parent directory")
	})
}

func TestPragmaNameValue(t *testing.T) {
	tests := []struct {
		name      string
		cfg       config
		input     string
		wantName  string
		wantValue string
		wantErr   require.ErrorAssertionFunc
	}{
		{
			name:      "basic pragma",
			cfg:       config{memory: false},
			input:     "PRAGMA journal_mode=WAL",
			wantName:  "journal_mode",
			wantValue: "WAL",
		},
		{
			name:      "pragma with spaces",
			cfg:       config{memory: false},
			input:     "PRAGMA   cache_size  =   2000  ",
			wantName:  "cache_size",
			wantValue: "2000",
		},
		{
			name:      "pragma with trailing semicolon",
			cfg:       config{memory: false},
			input:     "PRAGMA synchronous=NORMAL;",
			wantName:  "synchronous",
			wantValue: "NORMAL",
		},
		{
			name:    "pragma with multiple semicolons",
			cfg:     config{memory: false},
			input:   "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;",
			wantErr: require.Error,
		},
		{
			name:    "invalid pragma format",
			cfg:     config{memory: false},
			input:   "PRAGMA invalid_format",
			wantErr: require.Error,
		},
		{
			name:      "mmap_size pragma with memory DB",
			cfg:       config{memory: true},
			input:     "PRAGMA mmap_size=1000",
			wantName:  "mmap_size",
			wantValue: "", // should be empty for memory DB
		},
		{
			name:      "mmap_size pragma with regular DB",
			cfg:       config{memory: false},
			input:     "PRAGMA mmap_size=1000",
			wantName:  "mmap_size",
			wantValue: "1000",
		},
		{
			name:      "pragma with numeric value",
			cfg:       config{memory: false},
			input:     "PRAGMA page_size=4096",
			wantName:  "page_size",
			wantValue: "4096",
		},
		{
			name:      "pragma with mixed case",
			cfg:       config{memory: false},
			input:     "PRAGMA Journal_Mode=WAL",
			wantName:  "journal_mode",
			wantValue: "WAL",
		},
		{
			name:    "empty pragma",
			cfg:     config{memory: false},
			input:   "PRAGMA =value",
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			gotName, gotValue, err := tt.cfg.pragmaNameValue(tt.input)
			tt.wantErr(t, err)

			if err == nil {
				require.Equal(t, tt.wantName, gotName)
				require.Equal(t, tt.wantValue, gotValue)
			}
		})
	}
}
