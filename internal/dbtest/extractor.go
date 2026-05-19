package dbtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/entry"
)

// FixtureExtractor extracts records from vunnel SQLite caches and writes them as fixtures.
type FixtureExtractor struct {
	vunnelRoot string // path to vunnel data directory (contains provider subdirs)
}

// NewFixtureExtractor creates an extractor for the given vunnel cache root.
// The vunnelRoot should be the path to the vunnel data directory containing
// provider subdirectories (e.g., "debian", "rhel", "nvd").
func NewFixtureExtractor(vunnelRoot string) *FixtureExtractor {
	return &FixtureExtractor{vunnelRoot: vunnelRoot}
}

// ExtractionBuilder provides a fluent API for extraction operations.
type ExtractionBuilder struct {
	extractor    *FixtureExtractor
	providerName string
	patterns     []string
}

// From specifies which provider's results.db to read from.
// The provider name should match a subdirectory in the vunnel data directory.
func (e *FixtureExtractor) From(providerName string) *ExtractionBuilder {
	return &ExtractionBuilder{
		extractor:    e,
		providerName: providerName,
	}
}

// Select adds patterns for record selection (LIKE matching).
// Patterns are wrapped with % for partial matching:
//   - "CVE-2024-1234" matches any record containing this CVE ID
//   - "debian:10" matches records in the debian:10 namespace
//   - "RHSA-2024:%" matches all 2024 RHSAs
func (b *ExtractionBuilder) Select(patterns ...string) *ExtractionBuilder {
	b.patterns = append(b.patterns, patterns...)
	return b
}

// WriteTo extracts matching records and writes them to a new fixture directory.
// The fixtureDir should be the path to the fixture root directory (provider
// subdirectory will be created inside). This also creates db.yaml and db.lock
// files to track the fixture's provenance.
func (b *ExtractionBuilder) WriteTo(fixtureDir string) error {
	return b.writeFixtureWithManifest(fixtureDir, false)
}

// AppendTo extracts matching records and appends them to an existing fixture.
// Existing records with the same ID are overwritten. This also updates the
// db.yaml and db.lock files to track the additional extraction.
func (b *ExtractionBuilder) AppendTo(fixtureDir string) error {
	return b.writeFixtureWithManifest(fixtureDir, true)
}

// writeFixture handles both WriteTo and AppendTo operations.
func (b *ExtractionBuilder) writeFixture(fixtureDir string, appendMode bool) error {
	// resolve paths and validate
	dbPath := filepath.Join(b.extractor.vunnelRoot, b.providerName, "results", "results.db")
	metadataPath := filepath.Join(b.extractor.vunnelRoot, b.providerName, "metadata.json")

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("results.db not found for provider %q at %s", b.providerName, dbPath)
	}

	// read provider metadata and query records
	originalState, records, err := b.loadProviderData(dbPath, metadataPath)
	if err != nil {
		return err
	}

	// write records and listing
	writer := provider.NewWorkspaceWriter(fixtureDir, b.providerName)
	files, err := b.writeRecords(writer, records, fixtureDir, appendMode)
	if err != nil {
		return err
	}

	if err := writer.WriteListing(files); err != nil {
		return fmt.Errorf("failed to write listing: %w", err)
	}

	// compute listing file with digest
	listingPath := filepath.Join(fixtureDir, b.providerName, "results", "listing.xxh64")
	listingFile, err := provider.NewFile(listingPath)
	if err != nil {
		return fmt.Errorf("failed to hash listing file: %w", err)
	}
	listingFile.Path = "results/listing.xxh64" // relative path for metadata

	// preserve original fixture timestamp if appending
	if appendMode {
		existingMetadataPath := filepath.Join(fixtureDir, b.providerName, "metadata.json")
		if existingState, err := provider.ReadState(existingMetadataPath); err == nil {
			originalState.Timestamp = existingState.Timestamp
		}
	}

	// create and write fixture state
	fixtureState := b.createFixtureState(originalState, listingFile)
	if err := writer.WriteState(fixtureState); err != nil {
		return fmt.Errorf("failed to write state: %w", err)
	}

	return nil
}

func (b *ExtractionBuilder) loadProviderData(dbPath, metadataPath string) (provider.State, []entry.Record, error) {
	originalState, err := provider.ReadState(metadataPath)
	if err != nil {
		return provider.State{}, nil, fmt.Errorf("failed to read provider metadata: %w", err)
	}

	records, err := entry.QueryRecords(dbPath, b.patterns)
	if err != nil {
		return provider.State{}, nil, fmt.Errorf("failed to query records: %w", err)
	}

	if len(records) == 0 {
		return provider.State{}, nil, fmt.Errorf("no records matched patterns: %v", b.patterns)
	}

	return *originalState, records, nil
}

func (b *ExtractionBuilder) writeRecords(writer *provider.WorkspaceWriter, records []entry.Record, fixtureDir string, appendMode bool) ([]provider.File, error) {
	// collect existing files if appending
	existingFiles := make(map[string]provider.File)
	if appendMode {
		var err error
		existingFiles, err = b.collectExistingFiles(fixtureDir)
		if err != nil {
			return nil, fmt.Errorf("failed to collect existing files: %w", err)
		}
	}

	// write each record as a flat file
	var files []provider.File
	for _, record := range records {
		filename := sanitizePath(record.ID) + ".json"
		file, err := writer.WriteResult(filename, record.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to write record %q: %w", record.ID, err)
		}
		files = append(files, *file)
		delete(existingFiles, filename)
	}

	// add remaining existing files
	for _, f := range existingFiles {
		files = append(files, f)
	}

	return files, nil
}

func (b *ExtractionBuilder) createFixtureState(originalState provider.State, listing *provider.File) provider.State {
	return provider.State{
		Provider:  originalState.Provider,
		Version:   originalState.Version,
		Processor: originalState.Processor,
		Schema:    originalState.Schema,
		URLs:      originalState.URLs,
		Timestamp: originalState.Timestamp,
		Store:     "flat-file",
		Listing:   listing,
	}
}

// collectExistingFiles reads existing result files from a fixture directory.
// Supports nested directory structures (e.g., results/debian@10/CVE-2024-1234.json).
func (b *ExtractionBuilder) collectExistingFiles(fixtureDir string) (map[string]provider.File, error) {
	resultsDir := filepath.Join(fixtureDir, b.providerName, "results")
	files := make(map[string]provider.File)

	// check if results directory exists
	if _, err := os.Stat(resultsDir); os.IsNotExist(err) {
		return files, nil
	}

	err := filepath.WalkDir(resultsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		// skip listing files
		if strings.HasSuffix(name, ".xxh64") || strings.HasSuffix(name, ".sha256") {
			return nil
		}

		file, err := provider.NewFile(path)
		if err != nil {
			return fmt.Errorf("failed to hash existing file %q: %w", path, err)
		}

		// get path relative to resultsDir for the key
		relPath, err := filepath.Rel(resultsDir, path)
		if err != nil {
			return err
		}

		// adjust path to be relative to provider directory
		file.Path = filepath.Join("results", relPath)
		files[relPath] = *file
		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

// sanitizePath converts an identifier into a safe relative path.
// Replaces ":" with "@" for Windows compatibility, keeps "/" for directory structure.
// Example: "debian:10/CVE-2024-1234" -> "debian@10/CVE-2024-1234"
func sanitizePath(id string) string {
	return strings.ReplaceAll(id, ":", "@")
}

// MultiProviderExtractor extends FixtureExtractor to support extracting from multiple providers.
type MultiProviderExtractor struct {
	extractor *FixtureExtractor
	builders  []*ExtractionBuilder
}

// FromMultiple starts a multi-provider extraction, returning a builder that allows
// adding multiple provider extractions.
func (e *FixtureExtractor) FromMultiple() *MultiProviderExtractor {
	return &MultiProviderExtractor{
		extractor: e,
	}
}

// Provider adds a provider extraction to the multi-provider builder.
func (m *MultiProviderExtractor) Provider(providerName string, patterns ...string) *MultiProviderExtractor {
	builder := &ExtractionBuilder{
		extractor:    m.extractor,
		providerName: providerName,
		patterns:     patterns,
	}
	m.builders = append(m.builders, builder)
	return m
}

// WriteTo extracts matching records from all providers and writes them to a new fixture directory.
func (m *MultiProviderExtractor) WriteTo(fixtureDir string) error {
	for _, builder := range m.builders {
		if err := builder.WriteTo(fixtureDir); err != nil {
			return fmt.Errorf("failed to extract from provider %q: %w", builder.providerName, err)
		}
	}
	return nil
}

// AppendTo extracts matching records from all providers and appends them to an existing fixture.
func (m *MultiProviderExtractor) AppendTo(fixtureDir string) error {
	for _, builder := range m.builders {
		if err := builder.AppendTo(fixtureDir); err != nil {
			return fmt.Errorf("failed to append from provider %q: %w", builder.providerName, err)
		}
	}
	return nil
}

// writeFixtureWithManifest writes the fixture and creates/updates db.yaml and db.lock files.
func (b *ExtractionBuilder) writeFixtureWithManifest(fixtureDir string, appendMode bool) error {
	// perform the actual extraction
	if err := b.writeFixture(fixtureDir, appendMode); err != nil {
		return err
	}

	// read provider state from vunnel cache
	providerState, err := readProviderState(b.extractor.vunnelRoot, b.providerName)
	if err != nil {
		return fmt.Errorf("failed to read provider state: %w", err)
	}

	// handle config (db.yaml)
	var config *FixtureConfig
	if appendMode {
		// read existing config and append new extraction
		config, err = ReadConfig(fixtureDir)
		if err != nil {
			// if no config exists, create a new one
			config = &FixtureConfig{
				AutoGenerate: true,
				Extractions:  make(map[string][]string),
			}
		}
	} else {
		config = &FixtureConfig{
			AutoGenerate: true,
			Extractions:  make(map[string][]string),
		}
	}

	// add/update this provider's patterns
	existing := config.Extractions[b.providerName]
	config.Extractions[b.providerName] = append(existing, b.patterns...)

	if err := config.Write(fixtureDir); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// handle lock (db.lock)
	var lock *FixtureLock
	if appendMode {
		// try to read existing lock
		lock, err = ReadLock(fixtureDir)
		if err != nil {
			// if no lock exists, create a new one
			lock = &FixtureLock{
				CreatedAt: time.Now().UTC(),
				Providers: make(map[string]ProviderState),
			}
		}
	} else {
		lock = &FixtureLock{
			CreatedAt: time.Now().UTC(),
			Providers: make(map[string]ProviderState),
		}
	}

	// add/update provider state
	lock.Providers[b.providerName] = providerState

	// compute content hash
	contentHash, err := ComputeFixtureContentHash(fixtureDir)
	if err != nil {
		return fmt.Errorf("failed to compute content hash: %w", err)
	}
	lock.ContentHash = contentHash

	if err := lock.Write(fixtureDir); err != nil {
		return fmt.Errorf("failed to write lock: %w", err)
	}

	return nil
}

// writeFixtureOnly writes just the fixture content without updating config/lock files.
// This is used internally for regeneration.
func (b *ExtractionBuilder) writeFixtureOnly(fixtureDir string, appendMode bool) error {
	return b.writeFixture(fixtureDir, appendMode)
}

// readProviderState reads the provider metadata from vunnel cache and returns a ProviderState.
func readProviderState(vunnelRoot, providerName string) (ProviderState, error) {
	metadataPath := filepath.Join(vunnelRoot, providerName, "metadata.json")
	state, err := provider.ReadState(metadataPath)
	if err != nil {
		return ProviderState{}, fmt.Errorf("failed to read metadata.json: %w", err)
	}

	return ProviderState{
		VunnelVersion: state.Processor,
		Timestamp:     state.Timestamp,
	}, nil
}
