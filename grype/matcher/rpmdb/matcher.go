package rpmdb

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/common"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/jinzhu/copier"
)

// the source-rpm field has something akin to "util-linux-ng-2.17.2-12.28.el6_9.2.src.rpm"
// in which case the pattern will extract out the following values for the named capture groups:
//		name = "util-linux-ng"
//		version = "2.17.2" (or, if there's an epoch, we'd expect a value like "4:2.17.2")
//		release = "12.28.el6_9.2"
//		arch = "src"
var rpmPackageNamePattern = regexp.MustCompile(`^(?P<name>.*)-(?P<version>.*)-(?P<release>.*)\.(?P<arch>[a-zA-Z][^.]+)(\.rpm)$`)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.RpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RpmDBMatcher
}

// nolint:funlen
func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	matches := make([]match.Match, 0)

	// let's match with a synthetic package that doesn't exist. We will create a new
	// package that matches the same name and version as what is contained in the
	// "sourceRPM" field.

	// Regarding RPM epoch and comparisons... RedHat is explicit that when an RPM
	// epoch is not specified that it should be assumed to be zero (see
	// https://github.com/rpm-software-management/rpm/issues/450). This comment from
	// RedHat is applicable for a project that has elected to not use epoch and has
	// not changed their version scheme at all --therefore it is safe to assume that
	// the epoch (though not specified) is 0. However, in cases where there may be a
	// non-zero epoch and it has been omitted from the version string it is NOT safe
	// to assume an epoch of 0... as this could lead to misleading comparison
	// results.

	// For example, take the perl-Errno package:
	//		name: 		perl-Errno
	//		version:	0:1.28-419.el8_4.1
	//		sourceRPM:	perl-5.26.3-419.el8_4.1.src.rpm

	// Say we have a vulnerability with the following information (note this is
	// against the SOURCE package "perl", not the target package, "perl-Errno"):
	// 		ID:					CVE-2020-10543
	//		Package Name:		perl
	//		Version constraint:	< 4:5.26.3-419.el8

	// Note that the vulnerability information has complete knowledge about the
	// version and it's lineage (epoch + version), however, the source package
	// information for perl-Errno does not include any information about epoch. With
	// the rule from RedHat we should assume a 0 epoch and make the comparison:

	//		0:5.26.3-419.el8 < 4:5.26.3-419.el8 = true! ... therefore we are vulnerable since epoch 0 < 4.
	//                                                  ... this is an INVALID comparison!

	// The problem with this is that sourceRPMs tend to not specify epoch even though
	// there may be a non-zero epoch for that package! This is important. The "more
	// correct" thing to do in this case is to drop the epoch:

	//		5.26.3-419.el8 < 5.26.3-419.el8 = false!    ... these are the SAME VERSION

	// There is still a problem with this approach: it essentially makes an
	// assumption that a missing epoch really is the SAME epoch to the other version
	// being compared (in our example, no perl epoch on one side means we should
	// really assume an epoch of 4 on the other side). This could still lead to
	// problems since an epoch delimits potentially non-comparable version lineages.

	sourceMatches, err := m.matchBySourceIndirection(store, d, p)
	if err != nil {
		return nil, fmt.Errorf("failed to match by source indirection: %w", err)
	}
	matches = append(matches, sourceMatches...)

	// let's match with the package given to us (direct match).

	// Regarding RPM epochs... we know that the package and vulnerability will have
	// well specified epochs since both are sourced from either the RPMDB directly or
	// the upstream RedHat vulnerability data. Note: this is very much UNLIKE our
	// matching on a source package above where the epoch could be dropped in the
	// reference data. This means that any missing epoch CAN be assumed to be zero,
	// as it falls into the case of "the project elected to NOT have a epoch for the
	// first version scheme" and not into any other case.

	// For this reason match exactly on a package we should be EXPLICIT about the
	// epoch (since downstream version comparison logic will strip the epoch during
	// comparison for the above mentioned reasons --essentially for the source RPM
	// case). To do this we fill in missing epoch values in the package versions with
	// an explicit 0.

	exactMatches, err := m.matchOnPackage(store, d, p)
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

func (m *Matcher) matchOnPackage(store vulnerability.ProviderByDistro, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	// we want to ensure that the version ALWAYS has an epoch specified...
	var modifiedPackage pkg.Package

	err := copier.Copy(&modifiedPackage, p)
	if err != nil {
		return nil, fmt.Errorf("failed to copy package: %w", err)
	}

	modifiedPackage.Version = addZeroEpicIfApplicable(p.Version)

	matches, err := common.FindMatchesByPackageDistro(store, d, modifiedPackage, m.Type())
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities by dpkg source indirection: %w", err)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the modified package).
	for idx := range matches {
		matches[idx].Package = p
	}

	return matches, nil
}

func addZeroEpicIfApplicable(version string) string {
	if strings.Contains(version, ":") {
		return version
	}
	return "0:" + version
}

func getNameAndELVersion(metadata pkg.RpmdbMetadata) (string, string) {
	groupMatches := internal.MatchCaptureGroups(rpmPackageNamePattern, metadata.SourceRpm)
	version := groupMatches["version"] + "-" + groupMatches["release"]
	return groupMatches["name"], version
}
