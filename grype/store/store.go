package store

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
)

type Store struct {
	vulnerability.Provider
	vulnerability.MetadataProvider
	match.ExclusionProvider
}
