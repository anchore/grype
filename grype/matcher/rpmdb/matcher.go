package rpmdb

import (
	"fmt"
	"regexp"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/common"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/jinzhu/copier"
)

// the source-rpm field has something akin to "util-linux-ng-2.17.2-12.28.el6_9.2.src.rpm"
// in which case the pattern will extract out "util-linux-ng" as the left-most capture group
// name, version, release, epoch, arch
var rpmPackageNamePattern = regexp.MustCompile(`^(?P<name>.*)-(?P<version>.*)-(?P<release>.*?)\.(?P<arch>.*)(\.rpm)$`)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.RpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RpmDBMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
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

func (m *Matcher) matchBySourceIndirection(store vulnerability.ProviderByDistro, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	metadata, ok := p.Metadata.(pkg.RpmdbMetadata)
	if !ok {
		return nil, nil
	}

	// ignore packages without source indirection hints
	if metadata.SourceRpm == "" {
		return []match.Match{}, nil
	}

	groupMatches := internal.MatchCaptureGroups(rpmPackageNamePattern, metadata.SourceRpm)
	if len(groupMatches) == 0 {
		log.Warnf("unable to extract name from SourceRPM for %s", p)
		return nil, nil
	}

	// note: the result is match is the full match followed by the sub matches, in our case we're interested in the first capture group
	var sourcePackageName = groupMatches["name"]

	// don't include matches if the source package name matches the current package name
	if sourcePackageName == p.Name {
		return []match.Match{}, nil
	}

	// use source package name for exact package name matching
	var indirectPackage pkg.Package

	err := copier.Copy(&indirectPackage, p)
	if err != nil {
		return nil, fmt.Errorf("failed to copy package: %w", err)
	}

	// use the source package name
	indirectPackage.Name = sourcePackageName
	indirectPackage.Version = groupMatches["version"]

	matches, err := common.FindMatchesByPackageDistro(store, d, indirectPackage, m.Type())
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities by dpkg source indirection: %w", err)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the indirect package)
	// however, we also want to keep the indirect package around for future reference
	for idx := range matches {
		matches[idx].Type = match.ExactIndirectMatch
		matches[idx].Package = p
	}

	return matches, nil
}
