package diff

import (
	"fmt"

	"github.com/spf13/afero"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/schemaver"
)

type Result struct {
	Schema    string        `json:"$schema"`
	Databases DatabaseDiff  `json:"databases"`
	Packages  []PackageDiff `json:"packages,omitempty"`
}

// DatabaseDiff holds metadata for both databases being compared.
type DatabaseDiff struct {
	// Before is the database before the diff was generated
	Before DatabaseInfo `json:"before"`
	After  DatabaseInfo `json:"after"`
}

// DatabaseInfo holds metadata about a single database.
type DatabaseInfo struct {
	BuildTimestamp string `json:"buildTimestamp"`
	ModelVersion   string `json:"modelVersion"`
	Revision       int    `json:"revision"`
	Checksum       string `json:"checksum,omitempty"`
}

// PackageDiff represents the vulnerability diff for a single package or CPE.
type PackageDiff struct {
	Ecosystem       string               `json:"ecosystem,omitempty"`
	Name            string               `json:"name"`
	CPE             string               `json:"cpe,omitempty"`
	Vulnerabilities VulnerabilityChanges `json:"vulnerabilities"`
}

// VulnerabilityChanges holds the added, removed, and modified vulnerabilities for a package.
type VulnerabilityChanges struct {
	Added    []VulnerabilityID `json:"added,omitempty"`
	Removed  []VulnerabilityID `json:"removed,omitempty"`
	Modified []VulnerabilityID `json:"modified,omitempty"`
}

// VulnerabilityID is a minimal vulnerability reference in diff output.
type VulnerabilityID struct {
	Provider string `json:"provider"`
	ID       string `json:"id"`
}

// newDatabaseInfo constructs a DatabaseInfo from a DB directory path by reading metadata.
func newDatabaseInfo(dbDir string) (*DatabaseInfo, error) {
	reader, err := v6.NewReader(v6.Config{DBDirPath: dbDir})
	if err != nil {
		return nil, fmt.Errorf("failed to open database at %s: %w", dbDir, err)
	}
	defer log.CloseAndLogError(reader, dbDir)

	meta, err := reader.GetDBMetadata()
	if err != nil {
		return nil, fmt.Errorf("failed to read DB metadata: %w", err)
	}

	desc := v6.DescriptionFromMetadata(meta)

	info := &DatabaseInfo{
		BuildTimestamp: desc.Built.String(),
		ModelVersion:   schemaver.New(meta.Model, meta.Revision, meta.Addition).String(),
		Revision:       meta.Revision,
	}

	// try to read the checksum from import metadata (optional — may not exist for extracted archives)
	importMeta, err := v6.ReadImportMetadata(afero.NewOsFs(), dbDir)
	if err == nil && importMeta != nil {
		info.Checksum = importMeta.Digest
	}

	return info, nil
}
