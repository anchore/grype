package commands

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/cmd/grype/cli/options"
	dbprovider "github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/tarutil"
)

// writeTestProviderWorkspace lays out a minimal vunnel-style workspace under
// root/<name>/ for use by the archive tests:
//
//	root/
//	└── <name>/
//	    ├── input/some-input-file.txt
//	    ├── results/results.db
//	    └── metadata.json   (Stale: false)
func writeTestProviderWorkspace(t *testing.T, root, name string) {
	t.Helper()
	pdir := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(filepath.Join(pdir, "input"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(pdir, "results"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(pdir, "input", "some-input-file.txt"), []byte("raw"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(pdir, "results", "results.db"), []byte("results"), 0644))

	state := dbprovider.State{
		Provider: name,
		Version:  1,
		Stale:    false,
	}
	b, err := json.MarshalIndent(state, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(pdir, "metadata.json"), b, 0644))
}

func TestArchiveProvider(t *testing.T) {
	tests := []struct {
		name           string
		resultsOnly    bool
		wantNames      *strset.Set
		wantStateStale bool
	}{
		{
			name:        "default config includes input",
			resultsOnly: false,
			wantNames: strset.New(
				"test-provider/input/some-input-file.txt",
				"test-provider/metadata.json",
				"test-provider/results/results.db",
			),
			wantStateStale: false,
		},
		{
			name:        "results only excludes input and marks metadata stale",
			resultsOnly: true,
			wantNames: strset.New(
				"test-provider/metadata.json",
				"test-provider/results/results.db",
			),
			wantStateStale: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeTestProviderWorkspace(t, root, "test-provider")

			archivePath := filepath.Join(t.TempDir(), "archive.tar")
			tw, err := tarutil.NewWriter(archivePath)
			require.NoError(t, err)

			opts := options.DefaultDatabaseBuild()
			opts.Provider.Root = root
			opts.Cache.ResultsOnly = tt.resultsOnly

			require.NoError(t, archiveProvider(opts, "test-provider", tw))
			require.NoError(t, tw.Close())

			f, err := os.Open(archivePath)
			require.NoError(t, err)
			defer f.Close()

			var state dbprovider.State
			foundNames := strset.New()
			tr := tar.NewReader(f)
			for {
				header, err := tr.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				require.NoError(t, err)
				foundNames.Add(header.Name)
				if header.Name == "test-provider/metadata.json" {
					require.NoError(t, json.NewDecoder(tr).Decode(&state))
				}
			}

			assert.True(t, foundNames.IsEqual(tt.wantNames),
				"archive contents mismatch:\n  got:  %v\n  want: %v", foundNames.List(), tt.wantNames.List())
			assert.Equal(t, tt.wantStateStale, state.Stale, "metadata.Stale flag")
		})
	}
}

func TestArchiveProvider_RestoresCWD(t *testing.T) {
	// archiveProvider chdirs into Provider.Root; on completion the cwd must be restored
	// so subsequent providers in the same run aren't operating from an unexpected dir.
	root := t.TempDir()
	writeTestProviderWorkspace(t, root, "alpine")

	cwdBefore, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() {
		// be defensive in case the test fails mid-run and leaves cwd in tempdir
		_ = os.Chdir(cwdBefore)
	})

	archivePath := filepath.Join(t.TempDir(), "archive.tar")
	tw, err := tarutil.NewWriter(archivePath)
	require.NoError(t, err)
	defer tw.Close()

	opts := options.DefaultDatabaseBuild()
	opts.Provider.Root = root

	require.NoError(t, archiveProvider(opts, "alpine", tw))

	cwdAfter, err := os.Getwd()
	require.NoError(t, err)
	assert.Equal(t, cwdBefore, cwdAfter, "cwd was not restored after archiveProvider")
}
