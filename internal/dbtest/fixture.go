package dbtest

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/OneOfOne/xxhash"

	"github.com/anchore/grype/grype/db/provider"
)

// parseFixtureProviders scans the fixture directory for provider subdirectories
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
func parseFixtureProviders(fixtureDir string) (provider.States, error) {
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
	metadataPath := filepath.Join(providerDir, "metadata.json")

	// check if metadata.json exists
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		return nil, nil
	}

	// ensure listing file exists, generate if needed
	resultsDir := filepath.Join(providerDir, "results")
	if err := ensureListingFile(resultsDir); err != nil {
		return nil, fmt.Errorf("failed to ensure listing file: %w", err)
	}

	// read the provider state using the standard vunnel format parser
	state, err := provider.ReadState(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read provider state: %w", err)
	}

	return state, nil
}

// ensureListingFile checks if a listing.xxh64 file exists in the results directory.
// If it doesn't exist, generates one by hashing all result files.
func ensureListingFile(resultsDir string) error {
	listingPath := filepath.Join(resultsDir, "listing.xxh64")

	// check if listing file exists
	if _, err := os.Stat(listingPath); err == nil {
		return nil
	}

	// check if results directory exists
	if _, err := os.Stat(resultsDir); os.IsNotExist(err) {
		// no results directory, nothing to list
		return nil
	}

	// generate listing file
	return generateListingFile(resultsDir, listingPath)
}

// generateListingFile creates a listing.xxh64 file with hashes of all result files.
// Format: <hash>  <relative-path>
func generateListingFile(resultsDir, listingPath string) error {
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		return fmt.Errorf("failed to read results directory: %w", err)
	}

	// collect result files (excluding listing files)
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// skip listing files
		if strings.HasSuffix(name, ".xxh64") || strings.HasSuffix(name, ".sha256") {
			continue
		}
		files = append(files, name)
	}

	// sort for determinism
	sort.Strings(files)

	// create listing file
	f, err := os.Create(listingPath)
	if err != nil {
		return fmt.Errorf("failed to create listing file: %w", err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, name := range files {
		filePath := filepath.Join(resultsDir, name)
		hash, err := hashFileXXH64(filePath)
		if err != nil {
			return fmt.Errorf("failed to hash file %q: %w", name, err)
		}

		// format: <hash>  results/<filename>
		// the path is relative to the provider directory
		relativePath := filepath.Join("results", name)
		if _, err := fmt.Fprintf(writer, "%s  %s\n", hash, relativePath); err != nil {
			return err
		}
	}

	return writer.Flush()
}

// hashFileXXH64 computes the xxhash64 of a file and returns it as a hex string.
func hashFileXXH64(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := xxhash.New64()
	buf := make([]byte, 32*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if _, err := hasher.Write(buf[:n]); err != nil {
				return "", err
			}
		}
		if err != nil {
			break
		}
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
