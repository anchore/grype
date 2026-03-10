// Package testdb builds real grype v6 sqlite databases from vunnel fixture
// files for use in unit tests. This exercises the full pipeline:
// vunnel JSON -> processor/transformer -> build.Writer -> sqlite -> Reader -> Provider.
//
// The database automatically includes all OS aliasing overrides (centos→rhel,
// etc.) and package ecosystem mappings via v6.InitialData().
//
// Fixture files are extracted from real vunnel results.db files using the
// extract-fixture tool in cmd/extract-fixture. Each fixture has a companion
// .meta.json sidecar that records the vunnel schema URL and provider name,
// so the correct processor can be selected at test time.
package testdb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	v6 "github.com/anchore/grype/grype/db/v6"
	v6build "github.com/anchore/grype/grype/db/v6/build"
	"github.com/anchore/grype/grype/vulnerability"
)

// sidecar matches the .meta.json file written by the extract-fixture tool.
type sidecar struct {
	Schema   string `json:"schema"`
	ID       string `json:"identifier"`
	Provider string `json:"provider"`
}

// Option configures a test database.
type Option func(t testing.TB, b *builder) error

type builder struct {
	writer     data.Writer
	dir        string
	processors []data.Processor
}

// New builds a real grype v6 sqlite database and returns a vulnerability.Provider
// backed by it. Each call creates an independent database in a temp directory.
//
// The DB automatically includes all OS aliasing overrides and package ecosystem
// mappings. Fixture data is loaded via WithVunnelFixture options.
func New(t testing.TB, opts ...Option) vulnerability.Provider {
	t.Helper()

	dir := t.TempDir()

	// build.NewWriter calls v6.NewWriter under the hood, which calls
	// NewLowLevelDB(empty=true) → InitialData() → writes all OS/package overrides.
	w, err := v6build.NewWriter(dir, nil, false, 100)
	if err != nil {
		t.Fatalf("testdb: creating writer: %v", err)
	}

	b := &builder{
		writer:     w,
		dir:        dir,
		processors: v6build.Processors(v6build.Config{}),
	}

	for _, opt := range opts {
		if err := opt(t, b); err != nil {
			t.Fatalf("testdb: applying option: %v", err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("testdb: closing writer: %v", err)
	}

	rdr, err := v6.NewReader(v6.Config{DBDirPath: dir})
	if err != nil {
		t.Fatalf("testdb: opening reader: %v", err)
	}

	prov := v6.NewVulnerabilityProvider(rdr)
	t.Cleanup(func() {
		prov.Close()
	})

	return prov
}

// WithVunnelFixture loads a vunnel JSON fixture through the real
// processor/transformer pipeline into the test database.
//
// fixturePath should point to a .json file extracted by the extract-fixture
// tool. A companion .meta.json sidecar must exist alongside it (same name
// with .meta.json extension instead of .json).
func WithVunnelFixture(fixturePath string) Option {
	return func(t testing.TB, b *builder) error {
		t.Helper()

		// Read sidecar metadata
		metaPath := strings.TrimSuffix(fixturePath, filepath.Ext(fixturePath)) + ".meta.json"
		metaBytes, err := os.ReadFile(metaPath)
		if err != nil {
			return fmt.Errorf("reading sidecar %s: %w", metaPath, err)
		}

		var meta sidecar
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			return fmt.Errorf("parsing sidecar %s: %w", metaPath, err)
		}

		// Read fixture payload (the item JSON that processors expect)
		itemBytes, err := os.ReadFile(fixturePath)
		if err != nil {
			return fmt.Errorf("reading fixture %s: %w", fixturePath, err)
		}

		// Find the matching processor by schema URL
		var proc data.Processor
		for _, candidate := range b.processors {
			if candidate.IsSupported(meta.Schema) {
				proc = candidate
				break
			}
		}
		if proc == nil {
			return fmt.Errorf("no processor supports schema %q (from %s)", meta.Schema, metaPath)
		}

		// Build a minimal provider.State for the processor
		now := time.Now()
		state := provider.State{
			Provider:  meta.Provider,
			Version:   1,
			Processor: "testdb",
			Timestamp: now,
		}

		// Process the fixture through the transformer pipeline
		entries, err := proc.Process(bytes.NewReader(itemBytes), state)
		if err != nil {
			return fmt.Errorf("processing fixture %s: %w", fixturePath, err)
		}

		// Write entries to the database
		if err := b.writer.Write(entries...); err != nil {
			return fmt.Errorf("writing entries from %s: %w", fixturePath, err)
		}

		return nil
	}
}
