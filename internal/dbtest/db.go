package dbtest

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// Matcher is the interface for vulnerability matchers.
type Matcher interface {
	Match(vulnerability.Provider, grypePkg.Package) ([]match.Match, []match.IgnoreFilter, error)
}

// DB wraps a vulnerability.Provider with metadata about the database.
// It implements the vulnerability.Provider interface by delegating to the internal provider.
type DB struct {
	// Name is a human-readable name for this database (e.g., "v6")
	Name string

	// SchemaVersion is the database schema version
	SchemaVersion int

	// Path is the path to the database directory
	Path string

	provider vulnerability.Provider
	closer   io.Closer
}

var _ vulnerability.Provider = &DB{}

// PackageSearchNames returns the package names to search for in the database.
func (db *DB) PackageSearchNames(p grypePkg.Package) []string {
	return db.provider.PackageSearchNames(p)
}

// FindVulnerabilities returns vulnerabilities matching all the provided criteria.
func (db *DB) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	return db.provider.FindVulnerabilities(criteria...)
}

// VulnerabilityMetadata returns the metadata associated with a vulnerability.
func (db *DB) VulnerabilityMetadata(ref vulnerability.Reference) (*vulnerability.Metadata, error) {
	return db.provider.VulnerabilityMetadata(ref)
}

// Close closes the database connection and releases resources.
func (db *DB) Close() error {
	if db.closer != nil {
		return db.closer.Close()
	}
	return nil
}

// String returns a string representation of the database.
func (db *DB) String() string {
	return fmt.Sprintf("DB{name=%s, schema=%d, path=%s}", db.Name, db.SchemaVersion, db.Path)
}

// MustMatch calls matcher.Match using this DB as the provider.
// Returns the matches, failing the test on error. This drops the
// IgnoreFilter return value for convenience.
func (db *DB) MustMatch(t *testing.T, matcher Matcher, p grypePkg.Package) []match.Match {
	t.Helper()
	matches, _, err := matcher.Match(db, p)
	require.NoError(t, err)
	return matches
}
