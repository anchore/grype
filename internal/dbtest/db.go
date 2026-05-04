package dbtest

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
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
var _ vulnerability.EOLChecker = &DB{}

// PackageSearchNames returns the package names to search for in the database.
func (db *DB) PackageSearchNames(p grypePkg.Package) []string {
	return db.provider.PackageSearchNames(p)
}

// FindVulnerabilities returns vulnerabilities matching all the provided criteria.
func (db *DB) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	return db.provider.FindVulnerabilities(criteria...)
}

// VulnerabilityMetadata returns the metadata associated with a vulnerability.
//
//nolint:staticcheck // keeping deprecated API for compatibility
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

// Match calls matcher.Match using this DB as the provider and returns a FindingsAssertion
// for fluent assertions. Fails the test on error. The returned assertion captures both
// the matches and the ignore filters; use FindingsAssertion.Ignores() to assert on the
// latter. Ignore-filter completeness is only enforced once Ignores() is called.
func (db *DB) Match(t *testing.T, matcher Matcher, p grypePkg.Package) *FindingsAssertion {
	t.Helper()
	matches, ignores, err := matcher.Match(db, p)
	require.NoError(t, err)
	return AssertFindingsAndIgnores(t, matches, ignores, p)
}

// GetOperatingSystemEOL returns the EOL and EOAS dates for the given distro.
// Implements vulnerability.EOLChecker by delegating to the underlying provider
// if it supports the interface.
func (db *DB) GetOperatingSystemEOL(d *distro.Distro) (eolDate, eoasDate *time.Time, err error) {
	if checker, ok := db.provider.(vulnerability.EOLChecker); ok {
		return checker.GetOperatingSystemEOL(d)
	}
	return nil, nil, nil
}
