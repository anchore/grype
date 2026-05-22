package commands

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/internal/tarutil"
)

func TestGetProviderNameFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{path: "alpine/results/results.db", want: "alpine"},
		{path: "alpine", want: "alpine"},
		{path: "alpine/", want: "alpine"},
		{path: "./alpine/metadata.json", want: "alpine"},
		{path: "", want: "."},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, getProviderNameFromPath(tt.path))
		})
	}
}

func TestDetectPathTraversal(t *testing.T) {
	root := "/work/data"
	tests := []struct {
		name        string
		cleanedPath string
		wantErr     bool
	}{
		{name: "inside root", cleanedPath: "/work/data/alpine/metadata.json", wantErr: false},
		{name: "exact root", cleanedPath: "/work/data", wantErr: false},
		{name: "outside root", cleanedPath: "/etc/passwd", wantErr: true},
		{name: "sibling dir", cleanedPath: "/work/other/file", wantErr: true},
		{name: "empty path ok", cleanedPath: "", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detectPathTraversal(root, tt.cleanedPath)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDetectLinkTraversal(t *testing.T) {
	root := "/work/data"
	tests := []struct {
		name        string
		cleanedPath string
		linkTarget  string
		wantErr     bool
	}{
		{name: "relative link inside root", cleanedPath: "/work/data/alpine/link", linkTarget: "metadata.json", wantErr: false},
		{name: "relative link escapes root", cleanedPath: "/work/data/alpine/link", linkTarget: "../../etc/passwd", wantErr: true},
		{name: "absolute link inside root", cleanedPath: "/work/data/alpine/link", linkTarget: "/work/data/alpine/file", wantErr: false},
		{name: "absolute link outside root", cleanedPath: "/work/data/alpine/link", linkTarget: "/etc/passwd", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detectLinkTraversal(root, tt.cleanedPath, tt.linkTarget)
			if tt.wantErr {
				require.Error(t, err, "expected traversal to be rejected for %s -> %s", tt.cleanedPath, tt.linkTarget)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestBackupRestoreRoundTrip exercises the full data-sync archive cycle:
// build a provider workspace, archive it with cache backup, then restore
// the archive into a fresh root and verify file equivalence.
func TestBackupRestoreRoundTrip(t *testing.T) {
	srcRoot := t.TempDir()
	writeTestProviderWorkspace(t, srcRoot, "alpine")

	archivePath := filepath.Join(t.TempDir(), "cache.tar.gz")

	// --- backup ---
	tw, err := tarutil.NewWriter(archivePath)
	require.NoError(t, err)

	backupOpts := options.DefaultDatabaseBuild()
	backupOpts.Provider.Root = srcRoot

	require.NoError(t, archiveProvider(backupOpts, "alpine", tw))
	require.NoError(t, tw.Close())

	// readProviderNamesFromTarGz sees the same providers we wrote
	names, err := readProviderNamesFromTarGz(archivePath)
	require.NoError(t, err)
	sort.Strings(names)
	assert.Equal(t, []string{"alpine"}, names)

	// --- restore ---
	dstRoot := t.TempDir()

	// extractTarGz runs relative to cwd; restore would chdir for us, but
	// we're calling extractTarGz directly to keep the test focused.
	cwdBefore, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(cwdBefore) })
	require.NoError(t, os.Chdir(dstRoot))

	f, err := os.Open(archivePath)
	require.NoError(t, err)
	defer f.Close()

	require.NoError(t, extractTarGz(f, strset.New("alpine")))

	// --- verify ---
	for _, rel := range []string{
		"alpine/input/some-input-file.txt",
		"alpine/metadata.json",
		"alpine/results/results.db",
	} {
		_, err := os.Stat(filepath.Join(dstRoot, rel))
		assert.NoError(t, err, "expected restored file %s", rel)
	}
}

func TestExtractTarGz_RejectsEmptySelection(t *testing.T) {
	srcRoot := t.TempDir()
	writeTestProviderWorkspace(t, srcRoot, "alpine")

	archivePath := filepath.Join(t.TempDir(), "cache.tar.gz")
	tw, err := tarutil.NewWriter(archivePath)
	require.NoError(t, err)

	opts := options.DefaultDatabaseBuild()
	opts.Provider.Root = srcRoot
	require.NoError(t, archiveProvider(opts, "alpine", tw))
	require.NoError(t, tw.Close())

	cwdBefore, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(cwdBefore) })
	require.NoError(t, os.Chdir(t.TempDir()))

	f, err := os.Open(archivePath)
	require.NoError(t, err)
	defer f.Close()

	// Selecting only a provider that isn't in the archive should error.
	err = extractTarGz(f, strset.New("wolfi"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no provider data was restored")
}
