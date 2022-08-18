package db

import v4 "github.com/anchore/grype/grype/db/v4"

// Closer lets receiver close the db connection and free any allocated db resources.
// It's especially useful if vulnerability DB loaded repeatedly during some periodic SBOM scanning process.
type Closer struct {
	v4.DBCloser
}
