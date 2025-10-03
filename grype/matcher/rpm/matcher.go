package rpm

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	MissingEpochStrategy string
}

func NewRpmMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.RpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RpmMatcher
}

//nolint:funlen
func (m *Matcher) Match(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match

	exactMatches, err := m.matchPackage(vp, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by exact package name: %w", err)
	}

	matches = append(matches, exactMatches...)

	sourceMatches, err := m.matchUpstreamPackages(vp, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by source indirection: %w", err)
	}
	matches = append(matches, sourceMatches...)

	return matches, nil, nil
}

// matchPackage matches the given package against the vulnerability provider (direct match).
//
// Regarding RPM epochs... we know that the package and vulnerability will have
// well-specified epochs since both are sourced from either the RPM DB directly or
// the upstream RedHat vulnerability data. Note: this is very much UNLIKE our
// matching on a source package above where the epoch could be dropped in the
// reference data. This means that any missing epoch CAN be assumed to be zero,
// as it falls into the case of "the project elected to NOT have an epoch for the
// first version scheme" and not into any other case.
//
// For this reason match exactly on a package, we should be EXPLICIT about the
// epoch (since downstream version comparison logic will strip the epoch during
// comparison for the above-mentioned reasons --essentially for the source RPM
// case). To do this, we fill in missing epoch values in the package versions with
// an explicit 0.
func (m *Matcher) matchPackage(vp vulnerability.Provider, p pkg.Package) ([]match.Match, error) {
	provider := result.NewProvider(vp, p, m.Type())

	// we want to ensure that the version ALWAYS has an epoch specified... but at the same time we do not want to modify the
	// original package that was passed in when making matches. This is why we create the provider with the original package
	// then patch the epoch into the version of the package that we are searching with.
	addEpochIfApplicable(&p)

	matches, err := m.findMatches(provider, p)
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities by dpkg source indirection: %w", err)
	}

	return matches, nil
}

// matchUpstreamPackages finds matches with a synthetic package based on the sourceRPM (indirect match).

// Regarding RPM epoch and comparisons... RedHat is explicit that when an RPM
// epoch is not specified that it should be assumed to be zero (see
// https://github.com/rpm-software-management/rpm/issues/450). This comment from
// RedHat is applicable for a project that has elected to not use epoch and has
// not changed their version scheme at all --therefore it is safe to assume that
// the epoch (though not specified) is 0. However, in cases where there may be a
// non-zero epoch and it has been omitted from the version string, it is NOT safe
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

//		0:5.26.3-419.el8 < 4:5.26.3-419.el8 = true! ... therefore, we've been vulnerable since epoch 0 < 4.
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
func (m *Matcher) matchUpstreamPackages(vp vulnerability.Provider, p pkg.Package) ([]match.Match, error) {
	provider := result.NewProvider(vp, p, m.Type())

	var matches []match.Match

	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indirectMatches, err := m.findMatches(provider, indirectPackage)
		if err != nil {
			return nil, fmt.Errorf("failed to find vulnerabilities for rpm upstream source package: %w", err)
		}
		matches = append(matches, indirectMatches...)
	}

	return matches, nil
}

func (m *Matcher) findMatches(provider result.Provider, searchPkg pkg.Package) ([]match.Match, error) {
	if searchPkg.Distro == nil {
		return nil, nil
	}
	if isUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
		return nil, nil
	}

	switch {
	case shouldUseRedhatEUSMatching(searchPkg.Distro):
		return redhatEUSMatches(provider, searchPkg, m.cfg.MissingEpochStrategy)
	default:
		return m.standardMatches(provider, searchPkg)
	}
}

func (m *Matcher) standardMatches(provider result.Provider, searchPkg pkg.Package) ([]match.Match, error) {
	// Create version with config embedded
	pkgVersion := version.NewWithConfig(
		searchPkg.Version,
		pkg.VersionFormat(searchPkg),
		version.ComparisonConfig{
			MissingEpochStrategy: m.cfg.MissingEpochStrategy,
		},
	)

	disclosures, err := provider.FindResults(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		internal.OnlyQualifiedPackages(searchPkg),
		internal.OnlyVulnerableVersions(pkgVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch disclosures for distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	return disclosures.ToMatches(), nil
}

func addEpochIfApplicable(p *pkg.Package) {
	meta, ok := p.Metadata.(pkg.RpmMetadata)
	ver := p.Version
	if ver == "" {
		return // no version to work with, so we should not bother with an epoch
	}
	switch {
	case strings.Contains(ver, ":"):
		// we already have an epoch embedded in the version string
		return
	case ok && meta.Epoch != nil:
		// we have an explicit epoch in the metadata
		p.Version = fmt.Sprintf("%d:%s", *meta.Epoch, ver)
	default:
		// no epoch was found, so we will add one
		p.Version = "0:" + ver
	}
}

func isUnknownVersion(v string) bool {
	return v == "" || strings.ToLower(v) == "unknown"
}
