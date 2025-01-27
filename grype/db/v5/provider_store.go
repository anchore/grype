package v5

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
)

type ProviderStore struct {
	vulnerability.Provider
	match.ExclusionProvider
}
