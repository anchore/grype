package bitnami

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/packageurl-go"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct{}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.BitnamiPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.BitnamiMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	// SPDX package names can be display names. Prefer the canonical Bitnami
	// package name from the PURL when looking up vulnerability records.
	name := p.Name
	if parsed, err := packageurl.FromString(p.PURL); err == nil && parsed.Type == packageurl.TypeBitnami {
		name = parsed.Name
	}
	return internal.MatchPackageByEcosystemPackageName(store, p, name, m.Type())
}
