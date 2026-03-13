package provider

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/OneOfOne/xxhash"
)

// WorkspaceWriter creates vunnel-compatible workspace directories.
// This follows the vunnel workspace format as defined in:
// https://github.com/anchore/vunnel/blob/main/src/vunnel/workspace.py
//
// Workspace layout:
//
//	{root}/{provider}/
//	├── metadata.json      # provider state
//	└── results/
//	    ├── {id}.json      # result files (flat-file store)
//	    └── listing.xxh64  # checksums file
type WorkspaceWriter struct {
	root     string
	provider string
}

// NewWorkspaceWriter creates a writer for a new workspace.
func NewWorkspaceWriter(root, providerName string) *WorkspaceWriter {
	return &WorkspaceWriter{
		root:     root,
		provider: providerName,
	}
}

// stateJSON is the JSON-serializable form of State for metadata.json.
// Field order and names match vunnel's workspace.State dataclass.
type stateJSON struct {
	Provider            string   `json:"provider"`
	Version             int      `json:"version"`
	DistributionVersion int      `json:"distribution_version,omitempty"`
	Processor           string   `json:"processor"`
	Schema              Schema   `json:"schema"`
	URLs                []string `json:"urls,omitempty"`
	Timestamp           string   `json:"timestamp"`
	Listing             *File    `json:"listing,omitempty"`
	Store               string   `json:"store"`
	Stale               bool     `json:"stale,omitempty"`
}

// WriteState writes the metadata.json file for the provider.
// The state is written in the vunnel workspace format.
func (w *WorkspaceWriter) WriteState(state State) error {
	providerDir := filepath.Join(w.root, w.provider)
	if err := os.MkdirAll(providerDir, 0755); err != nil {
		return fmt.Errorf("failed to create provider directory: %w", err)
	}

	statePath := filepath.Join(providerDir, "metadata.json")

	// format timestamp in ISO8601 format
	timestamp := state.Timestamp.UTC().Format(time.RFC3339)

	serializable := stateJSON{
		Provider:            state.Provider,
		Version:             state.Version,
		DistributionVersion: state.DistributionVersion,
		Processor:           state.Processor,
		Schema:              state.Schema,
		URLs:                state.URLs,
		Timestamp:           timestamp,
		Listing:             state.Listing,
		Store:               state.Store,
		Stale:               state.Stale,
	}

	data, err := json.MarshalIndent(serializable, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := os.WriteFile(statePath, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}

// WriteResult writes a single result file and returns its File entry.
// The content should be a vunnel envelope JSON with schema, identifier, and item fields.
// The filename can include subdirectories (e.g., "debian@10/CVE-2024-1234.json").
func (w *WorkspaceWriter) WriteResult(filename string, content []byte) (*File, error) {
	resultsDir := filepath.Join(w.root, w.provider, "results")
	resultPath := filepath.Join(resultsDir, filename)

	// create parent directories (handles nested paths like "debian@10/CVE-2024-1234.json")
	if err := os.MkdirAll(filepath.Dir(resultPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create results directory: %w", err)
	}

	//nolint:gosec // resultPath is constructed internally by the workspace writer, not user input
	if err := os.WriteFile(resultPath, content, 0600); err != nil {
		return nil, fmt.Errorf("failed to write result file: %w", err)
	}

	// compute xxh64 hash
	hasher := xxhash.New64()
	_, _ = hasher.Write(content)

	return &File{
		Path:      filepath.Join("results", filename),
		Digest:    hex.EncodeToString(hasher.Sum(nil)),
		Algorithm: "xxh64",
	}, nil
}

// CopyResultFrom copies a result file from another location into this workspace.
func (w *WorkspaceWriter) CopyResultFrom(sourcePath string) (*File, error) {
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read source file: %w", err)
	}

	filename := filepath.Base(sourcePath)
	return w.WriteResult(filename, content)
}

// WriteListing writes the listing.xxh64 file from the collected file entries.
// Format follows vunnel: "{xxh64_hex}  {relative_path}" (two spaces separator)
func (w *WorkspaceWriter) WriteListing(files []File) error {
	resultsDir := filepath.Join(w.root, w.provider, "results")
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	listingPath := filepath.Join(resultsDir, "listing.xxh64")

	f, err := os.Create(listingPath)
	if err != nil {
		return fmt.Errorf("failed to create listing file: %w", err)
	}
	defer f.Close()

	// sort for determinism
	sortedFiles := make([]File, len(files))
	copy(sortedFiles, files)
	sort.Slice(sortedFiles, func(i, j int) bool {
		return sortedFiles[i].Path < sortedFiles[j].Path
	})

	writer := bufio.NewWriter(f)
	for _, file := range sortedFiles {
		// vunnel format: "{hash}  {path}" with two spaces
		if _, err := fmt.Fprintf(writer, "%s  %s\n", file.Digest, file.Path); err != nil {
			return fmt.Errorf("failed to write listing entry: %w", err)
		}
	}

	return writer.Flush()
}

// Path returns the full path to the provider workspace directory.
func (w *WorkspaceWriter) Path() string {
	return filepath.Join(w.root, w.provider)
}

// ResultsPath returns the full path to the results directory.
func (w *WorkspaceWriter) ResultsPath() string {
	return filepath.Join(w.root, w.provider, "results")
}

// ListingPath returns the full path to the listing file.
func (w *WorkspaceWriter) ListingPath() string {
	return filepath.Join(w.root, w.provider, "results", "listing.xxh64")
}
