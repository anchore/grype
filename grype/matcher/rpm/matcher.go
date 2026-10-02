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

// IgnoreRelatedPackage reasons emitted by the rpm matcher family. Exported so
// callers and tests can reference the same strings without drift. Each reason
// flags vulnerabilities that should be suppressed on related packages (e.g.,
// language-ecosystem GHSAs that overlap a distro RPM by file ownership).
const (
	// IgnoreReasonDistroFixed - the RHEL/AlmaLinux disclosure marks the
	// package as already fixed at or past the package's version. Emitted by
	// the AlmaLinux matcher when the rhel disclosure path resolves a package
	// as no-longer-vulnerable.
	IgnoreReasonDistroFixed = "Distro Fixed"

	// IgnoreReasonDistroNotVulnerable - the distro vendor explicitly says the
	// package is unaffected (UnaffectedPackageHandle in v6, or the EUS-overlay
	// "fixed" rows in rhel_eus). Emitted by the standard rpm matcher and the
	// EUS matcher.
	IgnoreReasonDistroNotVulnerable = "Distro Not Vulnerable"

	// IgnoreReasonAlmaUnaffected - the AlmaLinux ALSA marks the package as
	// unaffected, including the ALSA itself plus each CVE the ALSA references
	// (alias unwind). Emitted only by the AlmaLinux matcher.
	IgnoreReasonAlmaUnaffected = "Alma Unaffected"
)

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	MissingEpochStrategy version.MissingEpochStrategy
	UseCPEsForEOL        bool
	UseCPEs              bool
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

func (m *Matcher) Match(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match
	var ignored []match.IgnoreFilter

	switch {
	case shouldUseAlmaLinuxMatching(p.Distro):
		almaMatches, ignores, err := m.matchAlmaLinux(vp, p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match AlmaLinux: %w", err)
		}
		matches = append(matches, almaMatches...)
		ignored = append(ignored, ignores...)

	case shouldUseRedhatEUSMatching(p.Distro):
		eusMatches, ignores, err := m.matchRedhatEUS(vp, p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match RedHat EUS: %w", err)
		}
		matches = append(matches, eusMatches...)
		ignored = append(ignored, ignores...)

	default:
		distroMatches, ignores, err := m.matchDistro(vp, p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match by distro: %w", err)
		}
		matches = append(matches, distroMatches...)
		ignored = append(ignored, ignores...)
	}

	// if configured, also search by CPEs, either for every package or only for packages from EOL distros
	searchByCPE := m.cfg.UseCPEs
	if !searchByCPE && m.cfg.UseCPEsForEOL && internal.IsDistroEOL(vp, p.Distro) {
		log.WithFields("package", p.Name, "distro", p.Distro).Debug("distro is EOL, searching by CPEs")
		searchByCPE = true
	}

	if searchByCPE {
		cpeMatches, ignores, err := internal.MatchPackageByCPEs(vp, p, m.Type())
		switch {
		case errors.Is(err, internal.ErrEmptyCPEMatch):
			log.WithFields("package", p.Name).Debug("package has no CPEs to match by")
		case err != nil:
			log.WithFields("package", p.Name, "error", err).Debug("failed to match by CPEs")
		default:
			matches = append(matches, cpeMatches...)
			ignored = append(ignored, ignores...)
		}
	}

	return matches, ignored, nil
}

// matchAlmaLinux handles AlmaLinux-specific matching logic that considers both binary and upstream packages
// This must be called at the top level (before the binary/upstream split) because AlmaLinux matching
// needs to search for RHEL disclosures for both the binary package and its upstreams, then filter
// using AlmaLinux unaffected records for both the binary package and related packages
func (m *Matcher) matchAlmaLinux(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	if p.Distro == nil {
		return nil, nil, nil
	}
	if internal.IsUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	provider := result.NewProvider(vp, p, m.Type())

	// Add epoch if applicable for the binary package
	binaryPkg := p
	addEpochIfApplicable(&binaryPkg)

	// Call almaLinuxMatches with both the binary package and its upstreams
	return almaLinuxMatchesWithUpstreams(provider, p, binaryPkg)
}

// matchRedhatEUS searches the binary package and, as source packages, its upstreams.
//
// Regarding RPM epochs for the binary package... we know that the package and vulnerability will
// have well-specified epochs since both are sourced from either the RPM DB directly or the upstream
// RedHat vulnerability data. Note: this is very much UNLIKE our matching on a source package below
// where the epoch could be dropped in the reference data. This means that any missing epoch CAN be
// assumed to be zero, as it falls into the case of "the project elected to NOT have an epoch for the
// first version scheme" and not into any other case.
//
// For this reason, to match exactly on a package we should be EXPLICIT about the epoch (since
// downstream version comparison logic will strip the epoch during comparison for the
// above-mentioned reasons -- essentially for the source RPM case). To do this, we fill in missing
// epoch values in the package versions with an explicit 0, on a copy.
func (m *Matcher) matchRedhatEUS(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	provider := result.NewProvider(vp, p, m.Type())

	binaryPkg := p
	addEpochIfApplicable(&binaryPkg)

	matches, ignored, err := m.eusMatches(provider, p, binaryPkg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find vulnerabilities by exact package name: %w", err)
	}

	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		// upstreams are tagged arch "src", so binary-arch records are rejected
		indirectMatches, ignores, err := m.eusMatches(provider, p, indirectPackage)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to find vulnerabilities for rpm upstream source package: %w", err)
		}
		matches = append(matches, indirectMatches...)
		ignored = append(ignored, ignores...)
	}

	return matches, ignored, nil
}

func (m *Matcher) eusMatches(provider result.Provider, target, searchPkg pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	if searchPkg.Distro == nil {
		return nil, nil, nil
	}
	if internal.IsUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}
	return redhatEUSMatches(provider, target, searchPkg, m.cfg.MissingEpochStrategy)
}

// matchDistro searches the binary package, with an explicit epoch (see matchRedhatEUS), and its
// upstreams, without one, for the reasons below.
//
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
func (m *Matcher) matchDistro(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	searchPkg := p
	if !internal.IsUnknownVersion(searchPkg.Version) {
		// "0:unknown" would defeat the search's own unknown-version check
		addEpochIfApplicable(&searchPkg)
	}

	versionConfig := version.ComparisonConfig{
		MissingEpochStrategy: m.cfg.MissingEpochStrategy,
	}

	vulnerable, notVulnerable, err := internal.FindResultsByDistroAcrossUpstreams(vp, searchPkg, &p, m.Type(), &versionConfig)
	if err != nil {
		return nil, nil, err
	}

	return vulnerable.ToMatches(p), internal.OwnershipIgnores(p, IgnoreReasonDistroNotVulnerable, notVulnerable.Vulnerabilities()...), nil
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
