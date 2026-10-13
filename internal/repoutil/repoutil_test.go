package repoutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoot_FindsModuleRootWithoutGit(t *testing.T) {
	// an empty PATH makes git unavailable, so only the go.mod lookup can succeed
	t.Setenv("PATH", "")

	root, err := Root()
	require.NoError(t, err)

	wd, err := os.Getwd()
	require.NoError(t, err)
	// this package lives at <root>/internal/repoutil
	assert.Equal(t, filepath.Dir(filepath.Dir(wd)), root)
}

func TestDeclaresModule(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     bool
	}{
		{
			name:     "grype module",
			contents: "module github.com/anchore/grype\n\ngo 1.26\n",
			want:     true,
		},
		{
			name:     "other module",
			contents: "module github.com/anchore/syft\n",
			want:     false,
		},
		{
			name:     "module path that only shares a prefix",
			contents: "module github.com/anchore/grype/test/fixture\n",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goMod := filepath.Join(t.TempDir(), "go.mod")
			require.NoError(t, os.WriteFile(goMod, []byte(tt.contents), 0o600))
			assert.Equal(t, tt.want, declaresModule(goMod))
		})
	}

	assert.False(t, declaresModule(filepath.Join(t.TempDir(), "go.mod")), "missing file")
}
