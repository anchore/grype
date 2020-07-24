package dpkg

import (
	"fmt"

	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/matcher/common"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
	"github.com/jinzhu/copier"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []pkg.Type {
	return []pkg.Type{pkg.DebPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.DpkgMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d distro.Distro, p *pkg.Package) ([]match.Match, error) {
	matches := make([]match.Match, 0)

	sourceMatches, err := m.matchBySourceIndirection(store, d, p)
	if err != nil {
		return nil, fmt.Errorf("failed to match by source indirection: %w", err)
	}
	matches = append(matches, sourceMatches...)

	exactMatches, err := common.FindMatchesByPackageDistro(store, d, p, m.Type())
	if err != nil {
		return nil, fmt.Errorf("failed to match by exact package name: %w", err)
	}
	matches = append(matches, exactMatches...)

	return matches, nil
}

func (m *Matcher) matchBySourceIndirection(store vulnerability.ProviderByDistro, d distro.Distro, p *pkg.Package) ([]match.Match, error) {
	value, ok := p.Metadata.(pkg.DpkgMetadata)
	if !ok {
		return nil, fmt.Errorf("bad dpkg metadata type='%T'", value)
	}
	// grab source package name from metadata
	sourcePkgName := value.Source

	// ignore packages without source indirection hints
	if sourcePkgName == "" {
		return []match.Match{}, nil
	}

	// use source package name for exact package name matching
	var indirectPackage pkg.Package

	// TODO: we should add a copy() function onto package instead of relying on a 3rd party package
	err := copier.Copy(&indirectPackage, p)
	if err != nil {
		return nil, fmt.Errorf("failed to copy package: %w", err)
	}

	// use the source package name
	indirectPackage.Name = sourcePkgName

	matches, err := common.FindMatchesByPackageDistro(store, d, &indirectPackage, m.Type())
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities by dkpg source indirection: %w", err)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the indirect package)
	// however, we also want to keep the indirect package around for future reference
	for idx := range matches {
		matches[idx].Type = match.ExactIndirectMatch
		matches[idx].Package = p
		matches[idx].IndirectPackage = &indirectPackage
		matches[idx].Matcher = m.Type()
	}

	return matches, nil
}
