package reader

import (
	"fmt"

	"github.com/alicebob/sqlittle"
	v1 "github.com/anchore/grype/grype/db/v1"
	"github.com/anchore/grype/grype/db/v1/model"
)

// Reader holds an instance of the database connection.
type Reader struct {
	db *sqlittle.DB
}

// CleanupFn is a callback for closing a DB connection.
type CleanupFn func() error

// New creates a new instance of the store.
func New(dbFilePath string) (*Reader, CleanupFn, error) {
	d, err := Open(&config{
		dbPath:    dbFilePath,
		overwrite: false,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create a new connection to sqlite3 db: %s", err)
	}

	return &Reader{
		db: d,
	}, d.Close, nil
}

// GetID fetches the metadata about the databases schema version and build time.
func (b *Reader) GetID() (*v1.ID, error) {
	var scanErr error
	total := 0
	var m model.IDModel
	err := b.db.Select(model.IDTableName, func(row sqlittle.Row) {
		total++

		if scanErr = row.Scan(&m.BuildTimestamp, &m.SchemaVersion); scanErr != nil {
			return
		}
	}, "build_timestamp", "schema_version")

	if err != nil {
		return nil, fmt.Errorf("unable to query for ID: %w", err)
	}
	if scanErr != nil {
		return nil, scanErr
	}

	id, err := m.Inflate()
	if err != nil {
		return nil, err
	}

	switch {
	case total == 0:
		return nil, nil
	case total > 1:
		return nil, fmt.Errorf("discovered more than one DB ID")
	}

	return &id, nil
}

// GetVulnerability retrieves one or more vulnerabilities given a namespace and package name.
func (b *Reader) GetVulnerability(namespace, name string) ([]v1.Vulnerability, error) {
	var scanErr error
	var vulnerabilityModels []model.VulnerabilityModel

	err := b.db.IndexedSelectEq(model.VulnerabilityTableName, model.GetVulnerabilityIndexName, sqlittle.Key{name, namespace}, func(row sqlittle.Row) {
		var m model.VulnerabilityModel

		if err := row.Scan(&m.Namespace, &m.PackageName, &m.ID, &m.RecordSource, &m.VersionConstraint, &m.VersionFormat, &m.CPEs, &m.ProxyVulnerabilities, &m.FixedInVersion); err != nil {
			scanErr = fmt.Errorf("unable to scan over row: %w", err)
			return
		}

		vulnerabilityModels = append(vulnerabilityModels, m)
	}, "namespace", "package_name", "id", "record_source", "version_constraint", "version_format", "cpes", "proxy_vulnerabilities", "fixed_in_version")
	if err != nil {
		return nil, fmt.Errorf("unable to query: %w", err)
	}
	if scanErr != nil {
		return nil, scanErr
	}

	vulnerabilities := make([]v1.Vulnerability, 0, len(vulnerabilityModels))

	for _, m := range vulnerabilityModels {
		vulnerability, err := m.Inflate()
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vulnerability)
	}

	return vulnerabilities, nil
}

// GetVulnerabilityMetadata retrieves metadata for the given vulnerability ID relative to a specific record source.
func (b *Reader) GetVulnerabilityMetadata(id, recordSource string) (*v1.VulnerabilityMetadata, error) {
	total := 0
	var m model.VulnerabilityMetadataModel
	var scanErr error

	err := b.db.PKSelect(model.VulnerabilityMetadataTableName, sqlittle.Key{id, recordSource}, func(row sqlittle.Row) {
		total++

		if err := row.Scan(&m.ID, &m.RecordSource, &m.Severity, &m.Links, &m.Description, &m.CvssV2.String, &m.CvssV3.String); err != nil {
			scanErr = fmt.Errorf("unable to scan over row: %w", err)
			return
		}
	}, "id", "record_source", "severity", "links", "description", "cvss_v2", "cvss_v3")
	if err != nil {
		return nil, fmt.Errorf("unable to query: %w", err)
	}
	if scanErr != nil {
		return nil, scanErr
	}

	switch {
	case total == 0:
		return nil, nil
	case total > 1:
		return nil, fmt.Errorf("discovered more than one DB metadata record")
	}

	if m.CvssV2.String != "" {
		m.CvssV2.Valid = true
	}

	if m.CvssV3.String != "" {
		m.CvssV3.Valid = true
	}

	metadata, err := m.Inflate()
	if err != nil {
		return nil, err
	}

	return &metadata, nil
}
