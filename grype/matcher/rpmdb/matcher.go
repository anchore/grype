package rpmdb

import (
	"fmt"
	"regexp"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/common"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/jinzhu/copier"
)

// the source-rpm field has something akin to "util-linux-ng-2.17.2-12.28.el6_9.2.src.rpm"
// in which case the pattern will extract out "util-linux-ng" as the left-most capture group
var rpmPackageNamePattern = regexp.MustCompile(`(?P<name>^[a-zA-Z0-9\-]+)-\d+\.`)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []pkg.Type {
	return []pkg.Type{pkg.RpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RpmDBMatcher
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
	value, ok := p.Metadata.(pkg.RpmMetadata)
	if !ok {
		return nil, fmt.Errorf("bad rpmdb metadata type='%T'", value)
	}

	// ignore packages without source indirection hints
	if value.SourceRpm == "" {
		return []match.Match{}, nil
	}

	// convert the source-rpm package name (e.g. util-linux-ng-2.17.2-12.28.el6_9.2.src.rpm) to a package name (util-linux-ng)
	groupMatches := rpmPackageNamePattern.FindStringSubmatch(value.SourceRpm)
	if len(groupMatches) == 0 {
		return []match.Match{}, nil
	} else if len(groupMatches) > 2 {
		// TODO: we should not do this
		return []match.Match{}, fmt.Errorf("found multiple RPM packages matches: %+v", groupMatches)
	}
	// note: the result is match is the full match followed by the sub matches, in our case we're interested in the first capture group
	sourceRpmPackageName := groupMatches[1]

	// don't include matches if the source package name matches the current package name
	if sourceRpmPackageName == p.Name {
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
	indirectPackage.Name = sourceRpmPackageName

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
