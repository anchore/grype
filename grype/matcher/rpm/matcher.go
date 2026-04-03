package rpm

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	MissingEpochStrategy version.MissingEpochStrategy
	UseCPEsForEOL        bool
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
	var ignoreFilters []match.IgnoreFilter

	// Handle AlmaLinux matching at the top level before the binary/upstream split
	// AlmaLinux matching needs to handle both binary and upstream packages internally
	if p.Distro != nil && shouldUseAlmaLinuxMatching(p.Distro) {
		almaMatches, err := m.matchAlmaLinux(vp, p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match AlmaLinux: %w", err)
		}
		matches = append(matches, almaMatches...)
	} else {
		// For non-AlmaLinux distros, use the standard binary/upstream split
		exactMatches, exactIgnores, err := m.matchPackage(vp, p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match by exact package name: %w", err)
		}

		matches = append(matches, exactMatches...)
		ignoreFilters = append(ignoreFilters, exactIgnores...)

		sourceMatches, sourceIgnores, err := m.matchUpstreamPackages(vp, p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match by source indirection: %w", err)
		}
		matches = append(matches, sourceMatches...)
		ignoreFilters = append(ignoreFilters, sourceIgnores...)
	}

	// if configured, also search by CPEs for packages from EOL distros
	if m.cfg.UseCPEsForEOL && internal.IsDistroEOL(vp, p.Distro) {
		log.WithFields("package", p.Name, "distro", p.Distro).Debug("distro is EOL, searching by CPEs")
		cpeMatches, err := internal.MatchPackageByCPEs(vp, p, m.Type())
		switch {
		case errors.Is(err, internal.ErrEmptyCPEMatch):
			log.WithFields("package", p.Name).Debug("package has no CPEs for EOL fallback matching")
		case err != nil:
			log.WithFields("package", p.Name, "error", err).Debug("failed to match by CPEs for EOL distro")
		default:
			matches = append(matches, cpeMatches...)
		}
	}

	return matches, ignoreFilters, nil
}

// matchAlmaLinux handles AlmaLinux-specific matching logic that considers both binary and upstream packages
// This must be called at the top level (before the binary/upstream split) because AlmaLinux matching
// needs to search for RHEL disclosures for both the binary package and its upstreams, then filter
// using AlmaLinux unaffected records for both the binary package and related packages
func (m *Matcher) matchAlmaLinux(vp vulnerability.Provider, p pkg.Package) ([]match.Match, error) {
	if p.Distro == nil {
		return nil, nil
	}
	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil
	}

	provider := result.NewProvider(vp, p, m.Type())

	// Add epoch if applicable for the binary package
	binaryPkg := p
	addEpochIfApplicable(&binaryPkg)

	// Call almaLinuxMatches with both the binary package and its upstreams
	return almaLinuxMatchesWithUpstreams(provider, binaryPkg)
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
func (m *Matcher) matchPackage(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	// we want to ensure that the version ALWAYS has an epoch specified...
	addEpochIfApplicable(&p)

	if p.Distro == nil {
		return nil, nil, nil
	}
	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	if shouldUseRedhatEUSMatching(p.Distro) {
		provider := result.NewProvider(vp, p, m.Type())
		eusMatches, err := redhatEUSMatches(provider, p, m.cfg.MissingEpochStrategy)
		return eusMatches, nil, err
	}

	// Pass nil as catalogPkg for direct matches — MatchPackageByDistroWithOwnedFiles uses the
	// searchPkg directly, and distroMatchDetails treats nil catalogPkg as ExactDirectMatch.
	// File ownership is checked on searchPkg.Metadata which still has the RPM file records.
	cfg := &version.ComparisonConfig{MissingEpochStrategy: m.cfg.MissingEpochStrategy}
	return internal.MatchPackageByDistroWithOwnedFiles(vp, p, nil, m.Type(), cfg)
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
//
//	name: 		perl-Errno
//	version:	0:1.28-419.el8_4.1
//	sourceRPM:	perl-5.26.3-419.el8_4.1.src.rpm

// Say we have a vulnerability with the following information (note this is
// against the SOURCE package "perl", not the target package, "perl-Errno"):
//
//	ID:					CVE-2020-10543
//	Package Name:		perl
//	Version constraint:	< 4:5.26.3-419.el8

// Note that the vulnerability information has complete knowledge about the
// version and it's lineage (epoch + version), however, the source package
// information for perl-Errno does not include any information about epoch. With
// the rule from RedHat we should assume a 0 epoch and make the comparison:
//
//	0:5.26.3-419.el8 < 4:5.26.3-419.el8 = true! ... therefore, we've been vulnerable since epoch 0 < 4.
//	                                              ... this is an INVALID comparison!

// The problem with this is that sourceRPMs tend to not specify epoch even though
// there may be a non-zero epoch for that package! This is important. The "more
// correct" thing to do in this case is to drop the epoch:
//
//	5.26.3-419.el8 < 5.26.3-419.el8 = false!    ... these are the SAME VERSION

// There is still a problem with this approach: it essentially makes an
// assumption that a missing epoch really is the SAME epoch to the other version
// being compared (in our example, no perl epoch on one side means we should
// really assume an epoch of 4 on the other side). This could still lead to
// problems since an epoch delimits potentially non-comparable version lineages.
func (m *Matcher) matchUpstreamPackages(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match
	var ignores []match.IgnoreFilter

	cfg := &version.ComparisonConfig{MissingEpochStrategy: m.cfg.MissingEpochStrategy}

	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		if indirectPackage.Distro == nil {
			continue
		}
		if isUnknownVersion(indirectPackage.Version) {
			log.WithFields("package", indirectPackage.Name).Trace("skipping package with unknown version")
			continue
		}

		if shouldUseRedhatEUSMatching(indirectPackage.Distro) {
			provider := result.NewProvider(vp, p, m.Type())
			eusMatches, err := redhatEUSMatches(provider, indirectPackage, m.cfg.MissingEpochStrategy)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to find vulnerabilities for rpm upstream source package: %w", err)
			}
			matches = append(matches, eusMatches...)
			continue
		}

		indirectMatches, indirectIgnores, err := internal.MatchPackageByDistroWithOwnedFiles(vp, indirectPackage, &p, m.Type(), cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to find vulnerabilities for rpm upstream source package: %w", err)
		}
		matches = append(matches, indirectMatches...)
		ignores = append(ignores, indirectIgnores...)
	}

	return matches, ignores, nil
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
