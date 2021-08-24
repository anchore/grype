package rpmdb

import (
	"fmt"
	"regexp"
	"strconv"

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
// in which case the pattern will extract out the following values for the named capture groups:
//		name = "util-linux-ng"
//		version = "2.17.2"
//		release = "12.28.el6_9.2"
//      arch = "src"
var rpmPackageNamePattern = regexp.MustCompile(`^(?P<name>.*)-(?P<version>.*)-(?P<release>.*)\.(?P<arch>[a-zA-Z][^.]+)(\.rpm)$`)

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
		return nil, nil
	}

	sourceName, sourceVersion := getNameAndELVersion(metadata)
	if sourceName == "" && sourceVersion == "" {
		log.Warnf("unable to extract name and version from SourceRPM=%q for %s@%s", metadata.SourceRpm, p.Name, p.Version)
		return nil, nil
	}

	// don't include matches if the source package name matches the current package name
	if sourceName == p.Name {
		return nil, nil
	}

	// use source package name for exact package name matching
	var indirectPackage pkg.Package

	err := copier.Copy(&indirectPackage, p)
	if err != nil {
		return nil, fmt.Errorf("failed to copy package: %w", err)
	}

	// use the source package name
	indirectPackage.Name = sourceName
	indirectPackage.Version = sourceVersion

	matches, err := common.FindMatchesByPackageDistro(store, d, indirectPackage, m.Type())
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities by dpkg source indirection: %w", err)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the indirect package).
	// The match details already contains the specific indirect package information used to make the match.
	for idx := range matches {
		matches[idx].Type = match.ExactIndirectMatch
		matches[idx].Package = p
	}

	return matches, nil
}

func getNameAndELVersion(metadata pkg.RpmdbMetadata) (string, string) {
	groupMatches := internal.MatchCaptureGroups(rpmPackageNamePattern, metadata.SourceRpm)
	version := groupMatches["version"] + "-" + groupMatches["release"]
	// source RPMs never specify epoch, however, leaving out the epoch makes comparisons with other versions that do
	// include epoch is invalid since: unset epoch < "0" epoch < "1" epoch < "2" epoch ...
	// The version extracted from here will always be used for comparison against another version (from the vulnerability
	// data) which may include epoch. For this reason the epoch from the original package is used (only if specified).
	if metadata.Epoch != nil {
		version = strconv.Itoa(*metadata.Epoch) + ":" + version
	}
	return groupMatches["name"], version
}
