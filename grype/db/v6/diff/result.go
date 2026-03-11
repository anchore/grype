package diff

import (
	"fmt"

	"github.com/spf13/afero"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/schemaver"
)

// Result is the top-level diff result shape
type Result struct {
	// Schema is the diff JSON schema of this diff result
	Schema string `json:"schema"`
	// Databases indicates the two databases used to create this diff
	Databases DatabaseDiff `json:"databases"`
	// Packages holds the package-based diff result
	Packages []PackageDiff `json:"packages,omitempty"`
}

// DatabaseDiff holds metadata for both databases being compared.
type DatabaseDiff struct {
	// Before is the starting database, generated chronologically first
	Before DatabaseInfo `json:"before"`
	// After is the next database, chronologically after the first
	After DatabaseInfo `json:"after"`
}

// DatabaseInfo holds metadata about a single database.
type DatabaseInfo struct {
	// BuildTimestamp is the timestamp in the database metadata
	BuildTimestamp string `json:"buildTimestamp"`
	// ModelVersion is the schema version of the database
	ModelVersion string `json:"modelVersion"`
	// Revision is the database revision
	Revision int `json:"revision"`
	// Checksum is the checksum of the database, calculated by the hydration process
	Checksum string `json:"checksum,omitempty"`
}

// PackageDiff represents the vulnerability diff for a single package or CPE.
type PackageDiff struct {
	// Ecosystem is the package ecosystem such as rpm, or cpe
	Ecosystem string `json:"ecosystem,omitempty"`
	// Name is the package name or CPE product
	Name string `json:"name"`
	// CPE is the CPE identifier for the package if this is a CPE-based package
	CPE string `json:"cpe,omitempty"`
	// Vulnerabilities is all the vulnerability changes between the two databases
	Vulnerabilities VulnerabilityChanges `json:"vulnerabilities"`
}

// VulnerabilityChanges holds the added, removed, and modified vulnerabilities for a package.
type VulnerabilityChanges struct {
	// Added results are results added that will newly match a specific package
	Added []VulnerabilityID `json:"added,omitempty"`
	// Removed results are results removed that will no longer match a specific package
	Removed []VulnerabilityID `json:"removed,omitempty"`
	// Modified results are results that have been modified which will match the same package
	Modified []VulnerabilityID `json:"modified,omitempty"`
}

// VulnerabilityID is a minimal vulnerability reference in diff output.
type VulnerabilityID struct {
	// Provider is the vulnerability provider such as github, nvd, or redhat
	Provider string `json:"provider"`
	// ID is the vulnerability identifier
	ID string `json:"id"`
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
