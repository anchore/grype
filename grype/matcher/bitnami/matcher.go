package bitnami

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"

	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct{}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.BitnamiPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.BitnamiMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoredMatch, error) {
	// Bitnami packages' metadata are built from the package URL
	// ref: https://github.com/anchore/syft/blob/main/syft/pkg/bitnami.go#L3-L13
	// ref: https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/bitnami/package.go#L18-L45
	return internal.MatchPackageByEcosystemAndPURL(store, p, m.Type(), true)
}
