package db

import v5 "github.com/nextlinux/griffon/griffon/db/v5"

// Closer lets receiver close the db connection and free any allocated db resources.
// It's especially useful if vulnerability DB loaded repeatedly during some periodic SBOM scanning process.
type Closer struct {
	v5.DBCloser
}
