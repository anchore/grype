package v5

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/distribution"
	"github.com/anchore/grype/grype/db/v5/store"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
)

// TODO: add NVDNamespace const to grype.db package?
const (
	nvdNamespace             = "nvd:cpe"
	providerMetadataFileName = "provider-metadata.json"
)

var _ data.Writer = (*writer)(nil)

type writer struct {
	dbPath string
	store  db.Store
	states provider.States

	// Batching infrastructure
	batchSize   int
	batchBuffer []func() error
	mu          sync.Mutex // Protect batch state

	// Metrics
	totalBatches int
}

type ProviderMetadata struct {
	Providers []Provider `json:"providers"`
}

type Provider struct {
	Name              string    `json:"name"`
	LastSuccessfulRun time.Time `json:"lastSuccessfulRun"`
}

func NewWriter(directory string, dataAge time.Time, states provider.States, batchSize int) (data.Writer, error) {
	dbPath := path.Join(directory, db.VulnerabilityStoreFileName)
	theStore, err := store.New(dbPath, true)
	if err != nil {
		return nil, fmt.Errorf("unable to create store: %w", err)
	}

	if err := theStore.SetID(db.NewID(dataAge)); err != nil {
		return nil, fmt.Errorf("unable to set DB ID: %w", err)
	}

	// Use default if not configured
	if batchSize == 0 {
		batchSize = 2000
	}

	return &writer{
		dbPath:      dbPath,
		store:       theStore,
		states:      states,
		batchSize:   batchSize,
		batchBuffer: make([]func() error, 0, batchSize),
	}, nil
}

func (w *writer) Write(entries ...data.Entry) error {
	log.WithFields("records", len(entries)).Trace("writing records to DB")
	for _, entry := range entries {
		if entry.DBSchemaVersion != db.SchemaVersion {
			return fmt.Errorf("wrong schema version: want %+v got %+v", db.SchemaVersion, entry.DBSchemaVersion)
		}

		switch row := entry.Data.(type) {
		case db.Vulnerability:
			// Batch the vulnerability write
			vuln := row
			if err := w.addToBatch(func() error {
				return w.store.AddVulnerability(vuln)
			}); err != nil {
				return fmt.Errorf("unable to batch vulnerability write: %w", err)
			}
		case db.VulnerabilityMetadata:
			// Normalize severity before batching
			normalizeSeverity(&row, w.store)
			metadata := row
			if err := w.addToBatch(func() error {
				return w.store.AddVulnerabilityMetadata(metadata)
			}); err != nil {
				return fmt.Errorf("unable to batch vulnerability metadata write: %w", err)
			}
		case db.VulnerabilityMatchExclusion:
			// Batch the exclusion write
			exclusion := row
			if err := w.addToBatch(func() error {
				return w.store.AddVulnerabilityMatchExclusion(exclusion)
			}); err != nil {
				return fmt.Errorf("unable to batch vulnerability match exclusion write: %w", err)
			}
		default:
			return fmt.Errorf("data entry is not of type vulnerability, vulnerability metadata, or exclusion: %T", row)
		}
	}

	return nil
}

// addToBatch adds an operation to the batch buffer and flushes if batch size is reached
func (w *writer) addToBatch(op func() error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.batchBuffer = append(w.batchBuffer, op)

	if len(w.batchBuffer) >= w.batchSize {
		return w.flushUnlocked()
	}
	return nil
}

// Flush executes all pending operations in the batch buffer
func (w *writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushUnlocked()
}

// flushUnlocked executes all pending operations without acquiring the lock (must be called with lock held)
func (w *writer) flushUnlocked() error {
	if len(w.batchBuffer) == 0 {
		return nil
	}

	log.WithFields(
		"operations", len(w.batchBuffer),
		"batch_size", w.batchSize,
	).Debug("flushing batch")

	for i, op := range w.batchBuffer {
		if err := op(); err != nil {
			return fmt.Errorf("batch operation %d failed: %w", i, err)
		}
	}

	w.batchBuffer = w.batchBuffer[:0]
	w.totalBatches++
	return nil
}

// metadataAndClose closes the database and returns its metadata.
// The reason this is a compound action is that getting the built time and
// schema version from the database is an operation on the open database,
// but the checksum must be computed after the database is compacted and closed.
func (w *writer) metadataAndClose() (*distribution.Metadata, error) {
	storeID, err := w.store.GetID()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch store ID: %w", err)
	}
	w.store.Close()
	hashStr, err := file.HashFile(afero.NewOsFs(), w.dbPath, sha256.New())
	if err != nil {
		return nil, fmt.Errorf("failed to hash database file (%s): %w", w.dbPath, err)
	}

	metadata := distribution.Metadata{
		Built:    storeID.BuildTimestamp,
		Version:  storeID.SchemaVersion,
		Checksum: "sha256:" + hashStr,
	}
	return &metadata, nil
}

func NewProviderMetadata() ProviderMetadata {
	return ProviderMetadata{
		Providers: make([]Provider, 0),
	}
}

func (w *writer) ProviderMetadata() *ProviderMetadata {
	metadata := NewProviderMetadata()
	// Set provider time from states
	for _, state := range w.states {
		metadata.Providers = append(metadata.Providers, Provider{
			Name:              state.Provider,
			LastSuccessfulRun: state.Timestamp,
		})
	}
	return &metadata
}

func (w *writer) Close() error {
	// Flush any remaining batched operations
	if err := w.Flush(); err != nil {
		return fmt.Errorf("unable to flush pending writes: %w", err)
	}

	metadata, err := w.metadataAndClose()
	if err != nil {
		return err
	}

	metadataPath := path.Join(filepath.Dir(w.dbPath), distribution.MetadataFileName)
	if err = metadata.Write(metadataPath); err != nil {
		return err
	}

	providerMetadataPath := path.Join(filepath.Dir(w.dbPath), providerMetadataFileName)
	if err = w.ProviderMetadata().Write(providerMetadataPath); err != nil {
		return err
	}

	log.WithFields(
		"path", w.dbPath,
		"total_batches", w.totalBatches,
	).Info("database created")
	log.WithFields("path", metadataPath).Debug("database metadata created")
	log.WithFields("path", providerMetadataPath).Debug("provider metadata created")

	return nil
}

func normalizeSeverity(metadata *db.VulnerabilityMetadata, reader db.VulnerabilityMetadataStoreReader) {
	metadata.Severity = string(data.ParseSeverity(metadata.Severity))
	if metadata.Severity != "" && strings.ToLower(metadata.Severity) != "unknown" {
		return
	}
	if !strings.HasPrefix(strings.ToLower(metadata.ID), "cve") {
		return
	}
	if strings.HasPrefix(metadata.Namespace, nvdNamespace) {
		return
	}
	m, err := reader.GetVulnerabilityMetadata(metadata.ID, nvdNamespace)
	if err != nil {
		log.WithFields("id", metadata.ID, "error", err).Warn("error fetching vulnerability metadata from NVD namespace")
		return
	}
	if m == nil {
		log.WithFields("id", metadata.ID).Trace("unable to find vulnerability metadata from NVD namespace")
		return
	}

	newSeverity := string(data.ParseSeverity(m.Severity))
	if newSeverity != metadata.Severity {
		log.WithFields("id", metadata.ID, "namespace", metadata.Namespace, "sev-from", metadata.Severity, "sev-to", newSeverity).Trace("overriding irrelevant severity with data from NVD record")
	}
	metadata.Severity = newSeverity
}

func (p ProviderMetadata) Write(path string) error {
	providerMetadataJSON, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal provider metadata: %w", err)
	}
	//nolint:gosec
	if err = os.WriteFile(path, providerMetadataJSON, 0644); err != nil {
		return fmt.Errorf("unable to write provider metadata: %w", err)
	}
	return nil
}
