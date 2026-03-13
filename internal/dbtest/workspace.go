package dbtest

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/grype/grype/db/provider"
)

// parseWorkspaceProviders scans the fixture directory for provider subdirectories
// and returns a list of provider.State objects ready for use with db.Build().
//
// Expected fixture structure:
//
//	fixture/
//	├── provider-name/
//	│   ├── metadata.json    # vunnel provider state
//	│   └── results/
//	│       ├── CVE-2020-1234.json
//	│       └── listing.xxh64  # optional, auto-generated if missing
//	└── another-provider/
//	    ├── metadata.json
//	    └── results/
//	        └── ...
func parseWorkspaceProviders(fixtureDir string) (provider.States, error) {
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read fixture directory: %w", err)
	}

	var states provider.States
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		providerDir := filepath.Join(fixtureDir, entry.Name())
		state, err := parseProviderState(providerDir)
		if err != nil {
			return nil, fmt.Errorf("failed to parse provider %q: %w", entry.Name(), err)
		}
		if state != nil {
			states = append(states, *state)
		}
	}

	return states, nil
}

// parseProviderState reads a provider directory and returns a provider.State.
// If no metadata.json exists, returns nil (skip this directory).
func parseProviderState(providerDir string) (*provider.State, error) {
	ws := provider.NewWorkspaceFromExisting(providerDir)

	// check if metadata.json exists
	if _, err := os.Stat(ws.StatePath()); os.IsNotExist(err) {
		return nil, nil
	}

	// ensure listing file exists, generate if needed
	if err := ws.EnsureListingFile(); err != nil {
		return nil, fmt.Errorf("failed to ensure listing file: %w", err)
	}

	// read the provider state using the standard vunnel format parser
	state, err := ws.ReadState()
	if err != nil {
		return nil, fmt.Errorf("failed to read provider state: %w", err)
	}

	return state, nil
}
