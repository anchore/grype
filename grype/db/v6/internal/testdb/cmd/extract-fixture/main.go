// extract-fixture extracts individual records from vunnel results.db files
// and writes them as test fixture files for the testdb package.
//
// Usage:
//
//	go run ./grype/db/v6/internal/testdb/cmd/extract-fixture \
//	  --results-db /path/to/vunnel/debian/results/results.db \
//	  --id "debian:8/cve-2014-3566" \
//	  --provider debian \
//	  --output grype/grype/db/v6/internal/testdb/testdata/debian-8-cve-2014-3566.json
//
// Or in manifest mode, to re-extract all fixtures listed in a manifest file:
//
//	go run ./grype/db/v6/internal/testdb/cmd/extract-fixture \
//	  --manifest grype/grype/db/v6/internal/testdb/testdata/manifest.json \
//	  --vunnel-root /path/to/vunnel
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/glebarez/sqlite"
)

type manifest struct {
	Fixtures []fixtureSpec `json:"fixtures"`
}

type fixtureSpec struct {
	// Provider is the vunnel provider name (e.g., "debian", "nvd", "github").
	Provider string `json:"provider"`

	// ID is the record identifier within the results.db (e.g., "debian:8/cve-2014-3566").
	ID string `json:"id"`

	// Output is the path (relative to the manifest file) where the fixture JSON will be written.
	Output string `json:"output"`
}

// sidecar is written alongside each fixture as {name}.meta.json
type sidecar struct {
	Schema   string `json:"schema"`
	ID       string `json:"identifier"`
	Provider string `json:"provider"`
}

func main() {
	var (
		resultsDB  string
		recordID   string
		provider   string
		output     string
		manifFile  string
		vunnelRoot string
	)

	flag.StringVar(&resultsDB, "results-db", "", "path to a vunnel results.db file (single-record mode)")
	flag.StringVar(&recordID, "id", "", "record ID to extract (single-record mode)")
	flag.StringVar(&provider, "provider", "", "provider name for the sidecar metadata (single-record mode)")
	flag.StringVar(&output, "output", "", "output file path (single-record mode)")
	flag.StringVar(&manifFile, "manifest", "", "path to manifest.json (manifest mode)")
	flag.StringVar(&vunnelRoot, "vunnel-root", "", "root directory containing vunnel provider dirs (manifest mode)")
	flag.Parse()

	if manifFile != "" {
		if err := runManifest(manifFile, vunnelRoot); err != nil {
			log.Fatalf("manifest mode failed: %v", err)
		}
		return
	}

	if resultsDB == "" || recordID == "" || provider == "" || output == "" {
		flag.Usage()
		log.Fatal("single-record mode requires --results-db, --id, --provider, and --output")
	}

	if err := extractOne(resultsDB, recordID, provider, output); err != nil {
		log.Fatalf("extraction failed: %v", err)
	}
}

func runManifest(manifPath, vunnelRoot string) error {
	if vunnelRoot == "" {
		return fmt.Errorf("--vunnel-root is required in manifest mode")
	}

	data, err := os.ReadFile(manifPath)
	if err != nil {
		return fmt.Errorf("reading manifest: %w", err)
	}

	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parsing manifest: %w", err)
	}

	manifDir := filepath.Dir(manifPath)

	for _, f := range m.Fixtures {
		dbPath := filepath.Join(vunnelRoot, f.Provider, "results", "results.db")
		outPath := filepath.Join(manifDir, f.Output)

		fmt.Printf("extracting %s/%s -> %s\n", f.Provider, f.ID, outPath)

		if err := extractOne(dbPath, f.ID, f.Provider, outPath); err != nil {
			return fmt.Errorf("extracting %s/%s: %w", f.Provider, f.ID, err)
		}
	}

	fmt.Printf("extracted %d fixtures\n", len(m.Fixtures))
	return nil
}

func extractOne(dbPath, recordID, providerName, outputPath string) error {
	db, err := sql.Open("sqlite", dbPath+"?mode=ro&immutable=1")
	if err != nil {
		return fmt.Errorf("opening database %s: %w", dbPath, err)
	}
	defer db.Close()

	var rawRecord []byte
	err = db.QueryRow("SELECT record FROM results WHERE id = ?", recordID).Scan(&rawRecord)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("record %q not found in %s", recordID, dbPath)
		}
		return fmt.Errorf("querying record: %w", err)
	}

	// Parse the envelope to extract schema, identifier, and item
	var envelope struct {
		Schema     string          `json:"schema"`
		Identifier string          `json:"identifier"`
		Item       json.RawMessage `json:"item"`
	}
	if err := json.Unmarshal(rawRecord, &envelope); err != nil {
		return fmt.Errorf("parsing record envelope: %w", err)
	}

	// Write the item payload (what processors expect) as pretty-printed JSON
	var prettyItem json.RawMessage
	prettyItem, err = prettyJSON(envelope.Item)
	if err != nil {
		return fmt.Errorf("formatting item JSON: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	if err := os.WriteFile(outputPath, prettyItem, 0o644); err != nil {
		return fmt.Errorf("writing fixture: %w", err)
	}

	// Write sidecar metadata
	sc := sidecar{
		Schema:   envelope.Schema,
		ID:       envelope.Identifier,
		Provider: providerName,
	}
	scData, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling sidecar: %w", err)
	}
	scData = append(scData, '\n')

	scPath := strings.TrimSuffix(outputPath, filepath.Ext(outputPath)) + ".meta.json"
	if err := os.WriteFile(scPath, scData, 0o644); err != nil {
		return fmt.Errorf("writing sidecar: %w", err)
	}

	return nil
}

func prettyJSON(data json.RawMessage) (json.RawMessage, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')
	return out, nil
}
