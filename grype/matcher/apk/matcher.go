package apk

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.ApkPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.ApkMatcher
}

func (m *Matcher) Match(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	if p.Distro == nil {
		return nil, nil, nil
	}

	matchType := match.ExactDirectMatch
	searchPackage := p
	provider := result.NewProvider(vp, func(criteria []vulnerability.Criteria, v vulnerability.Vulnerability) match.Details {
		searchedByCPE, ok := getCPE(criteria)
		if ok {
			searchVersion := version.NewVersion(searchedByCPE.Attributes.Version, version.ApkFormat)
			return match.Details{internal.CPEMatchDetails(match.ApkMatcher, v, searchedByCPE, searchPackage, searchVersion)}
		}
		return internal.DistroMatchDetails(matchType, match.ApkMatcher, searchPackage, v)
	})

	// direct matches with the package itself
	matches, ignored, err := m.findMatchesForPackage(provider, p)
	if err != nil {
		return nil, nil, err
	}

	// TODO fix hack to pass matchType
	// remaining matches are indirect
	matchType = match.ExactIndirectMatch

	// indirect matches via the package's origin package
	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		searchPackage = indirectPackage
		indMatches, indIgnored, err := m.findMatchesForPackage(provider, indirectPackage)
		if err != nil {
			return nil, nil, err
		}
		matches.Merge(indMatches)
		ignored = append(ignored, indIgnored...)
	}

	return matches.ToMatches(p), ignored, err
}

func (m *Matcher) findMatchesForPackage(provider result.Provider, p pkg.Package) (result.ResultSet, []match.IgnoreFilter, error) {
	// find SecDB matches for the given package name and version
	allSecDbDisclosures, err := provider.FindResults(
		search.ByPackageName(p.Name),
		search.ByDistro(*p.Distro),
	)
	if err != nil {
		// TODO: we're dropping some....
		return nil, nil, err
	}

	secDbMatches := allSecDbDisclosures.Filter(
		internal.OnlyQualifiedPackages(p),
		internal.OnlyVulnerableVersions(version.NewVersionFromPkg(p)),
	)

	// find CPE-indexed vulnerability matches specific to the given package name and version
	cpeVulns, err := provider.FindResults(
		byAlpineCPEs(p),
	)
	if err != nil {
		return nil, nil, err
	}

	// get the set with no secDB entries
	cpeVulns = cpeVulns.Remove(allSecDbDisclosures)

	for _, upstreamPkg := range pkg.UpstreamPackages(p) {
		secDBVulnerabilitiesForUpstream, err := provider.FindResults(
			search.ByPackageName(upstreamPkg.Name),
			search.ByDistro(*upstreamPkg.Distro))
		if err != nil {
			return nil, nil, err
		}

		cpeVulns = cpeVulns.Remove(secDBVulnerabilitiesForUpstream)
	}

	// APK sources are also able to NAK vulnerabilities, so we want to return these as explicit ignores in order
	// to allow rules later to use these to ignore "the same" vulnerability found in "the same" locations
	naks, err := provider.FindResults(
		search.ByDistro(*p.Distro),
		search.ByPackageName(p.Name),
		nakConstraint,
	)
	if err != nil {
		// TODO: we're dropping some....
		return nil, nil, err
	}

	// remove NAKs from our immediate result list
	cpeVulns = cpeVulns.Remove(naks)

	var ignored []match.IgnoreFilter

	// we still need to raise up explicit ignore rules for every package that has a NAK vulnerability. Note that
	// this is separate from the combination of disclosures and resolutions that we have already created. This is
	// because NAKs should apply to results from other matchers, not just the APK matcher.
	for _, nak := range naks {
		meta, ok := p.Metadata.(pkg.ApkMetadata)
		if !ok {
			continue
		}

		for _, f := range meta.Files {
			ignored = append(ignored,
				match.IgnoreRule{
					Vulnerability:  string(nak.ID),
					IncludeAliases: true,
					Reason:         "Explicit APK NAK",
					Package: match.IgnoreRulePackage{
						Location: f.Path,
					},
				})
		}
	}

	cpeVulns = removeFixInfo(cpeVulns)

	results := secDbMatches.Merge(cpeVulns)

	return results, ignored, nil
}

func byAlpineCPEs(p pkg.Package) vulnerability.Criteria {
	var out []vulnerability.Criteria
	for _, c := range p.CPEs {
		searchVersion := c.Attributes.Version
		if searchVersion == "" {
			searchVersion = p.Version
		}
		c.Attributes.Version = internal.AlpineCPEComparableVersion(searchVersion)
		out = append(out, search.And(
			search.ByCPE(c),
			internal.OnlyVulnerableTargets(p),
			internal.OnlyVulnerableVersions(version.NewVersion(c.Attributes.Version, version.ApkFormat)),
			internal.OnlyNonWithdrawnVulnerabilities(),
			internal.OnlyQualifiedPackages(p),
		))
	}
	return search.Or(out...)
}

func getCPE(criteria []vulnerability.Criteria) (cpe.CPE, bool) {
	for _, criterion := range criteria {
		if c, ok := criterion.(*search.CPECriteria); ok && c != nil {
			return c.CPE, true
		}
	}
	return cpe.CPE{}, false
}

func removeFixInfo(vulns result.ResultSet) result.ResultSet {
	out := result.ResultSet{}
	for i := range vulns {
		incoming := vulns[i]
		for v := range incoming.Vulnerabilities {
			incoming.Vulnerabilities[v].Fix = vulnerability.Fix{
				Versions: nil,
				State:    vulnerability.FixStateUnknown,
			}
		}
		out[i] = incoming
	}
	return out
}

var (
	nakVersionString = version.MustGetConstraint("< 0", version.ApkFormat).String()
	// nakConstraint checks the exact version string for being an APK version with "< 0"
	nakConstraint = search.ByConstraintFunc(func(c version.Constraint) (bool, error) {
		return c.String() == nakVersionString, nil
	})
)
