package v5

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/afero"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/distribution"
	grypeDBStore "github.com/anchore/grype/grype/db/v5/store"
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
	store  grypeDB.Store
	states provider.States
}

type ProviderMetadata struct {
	Providers []Provider `json:"providers"`
}

type Provider struct {
	Name              string    `json:"name"`
	LastSuccessfulRun time.Time `json:"lastSuccessfulRun"`
}

func NewWriter(directory string, dataAge time.Time, states provider.States) (data.Writer, error) {
	dbPath := path.Join(directory, grypeDB.VulnerabilityStoreFileName)
	theStore, err := grypeDBStore.New(dbPath, true)
	if err != nil {
		return nil, fmt.Errorf("unable to create store: %w", err)
	}

	if err := theStore.SetID(grypeDB.NewID(dataAge)); err != nil {
		return nil, fmt.Errorf("unable to set DB ID: %w", err)
	}

	return &writer{
		dbPath: dbPath,
		store:  theStore,
		states: states,
	}, nil
}

func (w writer) Write(entries ...data.Entry) error {
	log.WithFields("records", len(entries)).Trace("writing records to DB")
	for _, entry := range entries {
		if entry.DBSchemaVersion != grypeDB.SchemaVersion {
			return fmt.Errorf("wrong schema version: want %+v got %+v", grypeDB.SchemaVersion, entry.DBSchemaVersion)
		}

		switch row := entry.Data.(type) {
		case grypeDB.Vulnerability:
			if err := w.store.AddVulnerability(row); err != nil {
				return fmt.Errorf("unable to write vulnerability to store: %w", err)
			}
		case grypeDB.VulnerabilityMetadata:
			normalizeSeverity(&row, w.store)
			if err := w.store.AddVulnerabilityMetadata(row); err != nil {
				return fmt.Errorf("unable to write vulnerability metadata to store: %w", err)
			}
		case grypeDB.VulnerabilityMatchExclusion:
			if err := w.store.AddVulnerabilityMatchExclusion(row); err != nil {
				return fmt.Errorf("unable to write vulnerability match exclusion to store: %w", err)
			}
		default:
			return fmt.Errorf("data entry is not of type vulnerability, vulnerability metadata, or exclusion: %T", row)
		}
	}

	return nil
}

// metadataAndClose closes the database and returns its metadata.
// The reason this is a compound action is that getting the built time and
// schema version from the database is an operation on the open database,
// but the checksum must be computed after the database is compacted and closed.
func (w writer) metadataAndClose() (*distribution.Metadata, error) {
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

func (w writer) ProviderMetadata() *ProviderMetadata {
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

func (w writer) Close() error {
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

	log.WithFields("path", w.dbPath).Info("database created")
	log.WithFields("path", metadataPath).Debug("database metadata created")
	log.WithFields("path", providerMetadataPath).Debug("provider metadata created")

	return nil
}

func normalizeSeverity(metadata *grypeDB.VulnerabilityMetadata, reader grypeDB.VulnerabilityMetadataStoreReader) {
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
