package grype

import (
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
)

// TODO: review this object more thoroughly post M6 prototype
type Store struct {
	VulnerabilityProvider         vulnerability.Provider
	VulnerabilityMetadataProvider vulnerability.MetadataProvider
	MatchExclusionProvider        match.ExclusionProvider
	Status                        *db.Status
}
