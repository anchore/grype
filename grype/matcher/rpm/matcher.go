package rpm

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.RpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RpmMatcher
}

//nolint:funlen
func (m *Matcher) Match(provider vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
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

	sourceMatches, err := m.matchUpstreamPackages(provider, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by source indirection: %w", err)
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

	exactMatches, err := m.matchPackage(provider, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by exact package name: %w", err)
	}

	matches = append(matches, exactMatches...)

	return matches, nil, nil
}

func (m *Matcher) matchUpstreamPackages(provider vulnerability.Provider, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indirectMatches, _, err := findMatches(provider, indirectPackage, match.ExactIndirectMatch, m.Type())
		if err != nil {
			return nil, fmt.Errorf("failed to find vulnerabilities for rpm upstream source package: %w", err)
		}
		matches = append(matches, indirectMatches...)
	}

	return matches, nil
}

func (m *Matcher) matchPackage(provider vulnerability.Provider, p pkg.Package) ([]match.Match, error) {
	// we want to ensure that the version ALWAYS has an epoch specified...
	originalPkg := p

	addEpochIfApplicable(&p)

	matches, _, err := findMatches(provider, p, match.ExactDirectMatch, m.Type())
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities by dpkg source indirection: %w", err)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the modified package).
	for idx := range matches {
		matches[idx].Package = originalPkg
	}

	return matches, nil
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

func findMatches(provider vulnerability.Provider, p pkg.Package, ty match.Type, upstreamMatcher match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	if p.Distro == nil {
		return nil, nil, nil
	}
	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	if isEUSContext(p.Distro) {
		return findEUSMatches(provider, p, ty, upstreamMatcher)
	}

	return internal.MatchPackageByDistro(provider, p, ty, upstreamMatcher)
}

func findEUSMatches(provider vulnerability.Provider, p pkg.Package, ty match.Type, upstreamMatcher match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	verObj := version.NewVersionFromPkg(p)

	distroWithoutEUS := *p.Distro
	distroWithoutEUS.Variant = "" // clear the EUS designator so that we can search for the base distro

	disclosures, err := provider.FindVulnerabilities(
		search.ByPackageName(p.Name),
		search.ByDistro(distroWithoutEUS), // e.g.  >= 9.0 && < 10
		internal.OnlyQualifiedPackages(p),
		// TODO: answer : we can never do this? well, can't do it for alma
		internal.OnlyVulnerableVersions(verObj), // TODO: we do less work by including this here, but if we were being pure about this we'd let the collection handle this
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch disclosures for distro=%q pkg=%q: %w", p.Distro, p.Name, err)
	}

	if len(disclosures) == 0 {
		return nil, nil, nil
	}

	c := internal.NewMatchFactory(p)

	c.AddVulnsAsDisclosures(
		internal.DisclosureConfig{
			KeepFixVersions: false, // this is already covered in resolutions
			MatchPrototype: internal.MatchPrototype{
				Type:    ty,
				Matcher: upstreamMatcher,
				SearchedBy: match.DistroParameters{
					Distro: match.DistroIdentification{
						Type:    p.Distro.Type.String(),
						Version: p.Distro.Version,
					},
					Package: match.PackageParameter{
						Name:    p.Name,
						Version: p.Version,
					},
				},
			},
			FoundByGenerator: func(v vulnerability.Vulnerability) any {
				return match.DistroResult{
					VulnerabilityID:   v.ID,
					VersionConstraint: v.Constraint.String(),
				}
			},
		},
		disclosures...)

	resolutions, err := provider.FindVulnerabilities(
		search.ByPackageName(p.Name),
		search.ByDistro(distroWithoutEUS), // e.g.  >= 9.0 && < 10
		search.ByDistroRange(
			search.DistroRange{
				Type: p.Distro.Type,
				// e.g.  >= 9.0+eus && <= 9.X+eus
				Ranges: []search.DistroOpenRange{
					{
						Version:  fmt.Sprintf("%s.0", p.Distro.MajorVersion()),
						Operator: version.GTE,
					},
					{
						// TODO: what if minor version is not specified?
						Version:  fmt.Sprintf("%s.%s", p.Distro.MajorVersion(), p.Distro.MinorVersion()),
						Operator: version.LTE,
					},
				},
				Variant: p.Distro.Variant,
				IDLike:  p.Distro.IDLike,
			},
		),
		internal.OnlyQualifiedPackages(p),
		// internal.OnlyVulnerableVersions(verObj), // this is applied within the collection, so is WRONG to apply here (will result in FPs)
	)

	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch resolutions for distro=%q pkg=%q: %w", p.Distro, p.Name, err)
	}

	c.AddVulnsAsResolutions(resolutions...)

	matches, ignored, err := c.Matches()
	return matches, ignored, err
}

func isUnknownVersion(v string) bool {
	return v == "" || strings.ToLower(v) == "unknown"
}

func isEUSContext(d *distro.Distro) bool {
	if d == nil {
		return false
	}

	return strings.ToLower(d.Variant) == "eus"
}
