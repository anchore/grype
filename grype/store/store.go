package store

import (
	"io"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
)

type Store struct {
	vulnerability.Provider
	vulnerability.MetadataProvider
	match.ExclusionProvider
	io.Closer
	V6 db.VulnerabilityProvider
}
