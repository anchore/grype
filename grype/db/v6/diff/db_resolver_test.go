package diff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
)

func TestResolveDB_keepsUserDirectoriesOnFailure(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string) (value, defaultDir string)
	}{
		{
			name: "directory without a database",
			setup: func(_ *testing.T, dir string) (string, string) {
				return dir, ""
			},
		},
		{
			name: "default directory without a database",
			setup: func(_ *testing.T, dir string) (string, string) {
				return "", dir
			},
		},
		{
			name: "invalid database file",
			setup: func(t *testing.T, dir string) (string, string) {
				dbFile := filepath.Join(dir, v6.VulnerabilityDBFileName)
				require.NoError(t, os.WriteFile(dbFile, []byte("not a database"), 0o600))
				return dbFile, ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			unrelated := filepath.Join(dir, "unrelated.txt")
			require.NoError(t, os.WriteFile(unrelated, []byte("keep me"), 0o600))

			value, defaultDir := tt.setup(t, dir)
			_, err := ResolveDB(value, defaultDir)
			require.Error(t, err)

			require.FileExists(t, unrelated)
		})
	}
}
