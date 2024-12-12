package v5

import (
	"io"

	"github.com/anchore/grype/grype/match"
)

type ProviderStore struct {
	VulnerabilityProvider
	VulnerabilityMetadataProvider
	match.ExclusionProvider
	io.Closer
}
