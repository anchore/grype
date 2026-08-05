package apk

import (
	"errors"
	"fmt"

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

var (
	nakVersionString = version.MustGetConstraint("< 0", version.ApkFormat).String()

	// nakConstraint checks the exact version string for being an APK version with "< 0"
	nakConstraint = search.ByConstraintFunc(func(c version.Constraint) (bool, error) {
		return c.String() == nakVersionString, nil
	})
)

type Matcher struct{}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.ApkPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.ApkMatcher
}

// Match get all matches and ignore filters from package distro and package origin
func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match
	var ignoreFilters []match.IgnoreFilter

	// direct matches with package itself (+ distro-fixed ignore rules when metadata implements FileOwner)
	directMatches, directIgnores, err := m.findMatchesForPackage(store, p, nil)
	if err != nil {
		return nil, nil, err
	}
	matches = append(matches, directMatches...)
	ignoreFilters = append(ignoreFilters, directIgnores...)

	// indirect matches, via package's origin package
	indirectMatches, indirectIgnores, err := m.findMatchesForOriginPackage(store, p)
	if err != nil {
		return nil, nil, err
	}
	matches = append(matches, indirectMatches...)
	ignoreFilters = append(ignoreFilters, indirectIgnores...)

	// APK sources are also able to NAK vulnerabilities, so we want to return these as explicit ignores in order
	// to allow rules later to use these to ignore "the same" vulnerability found in "the same" locations
	naks, err := m.findNaksForPackage(store, p)
	if err != nil {
		return nil, nil, err
	}
	ignoreFilters = append(ignoreFilters, naks...)

	return matches, ignoreFilters, nil
}

// cpeMatchesWithoutFixes find all relevant upstream match information from NVD by CPE
func (m *Matcher) cpeMatchesWithoutFixes(provider vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	// find CPE-indexed vulnerability matches specific to the given package name and version
	cpeMatches, ignored, err := internal.MatchPackageByCPEs(provider, p, m.Type())
	if err != nil {
		log.WithFields("package", p.Name, "error", err).Debug("failed to find CPE matches for package")
	}
	if p.Distro == nil {
		return cpeMatches, ignored, nil
	}

	// gather every security feed entry for this package (and its upstreams) so the CPE matches can be
	// reconciled against the feed by identity (vulnerability ID or alias) below.
	feedSet, err := vulnSetForPackage(provider, p)
	if err != nil {
		return nil, nil, err
	}

	// organize cpe matches by unique identifier
	cpeMatchesByID := matchesByID(cpeMatches)
	// version object will be used for constraint comparisons
	verObj := version.New(p.Version, pkg.VersionFormat(p))

	var finalCpeMatches []match.Match

	// get nvd matches which are not superceded by a more specific distro match
	for _, cpeMatchesForID := range cpeMatchesByID {
		unresolvedCpeMatches, err := cpeMatchesNotResolvedByFeed(feedSet, cpeMatchesForID, verObj)
		if err != nil {
			return nil, nil, err
		}
		finalCpeMatches = append(finalCpeMatches, unresolvedCpeMatches...)
	}

	return finalCpeMatches, ignored, nil
}

// cpeMatchesNotResolvedByFeed decides which CPE (NVD) matches for a single vulnerability to keep,
// given what the distro security feed knows about it. Matches are reconciled against the feed by
// identity (vulnerability ID or alias). A CPE match is kept when either:
//   - the vulnerability is not in the feed at all
//   - the vulnerability is in the feed and the feed still considers the package vulnerable at its version
//
// Note this does not itself deduplicate against the distro matches; that occurs later
func cpeMatchesNotResolvedByFeed(distroFeedSet result.Set, cpeMatchesForVuln []match.Match, verObj *version.Version) ([]match.Match, error) {
	// find distro security feed entries that overlap these CPE matches by identity (vulnerability ID
	// or alias) so that, for example, a CPE match keyed by a CVE is reconciled against a feed record
	// (e.g. a CGA) that lists the same CVE as an alias.
	feedVulnsForID := distroFeedSet.Intersection(newResultSet(matchVulnerabilities(cpeMatchesForVuln)...)).Vulnerabilities()
	if len(feedVulnsForID) == 0 {
		// these matches do not exist in security feed, so the CPE record(s) should be added to the matches
		// with unknown fix state, since NVD doesn't know when Alpine will fix things
		var cpeMatches []match.Match
		for _, nvdOnlyMatch := range cpeMatchesForVuln {
			if len(nvdOnlyMatch.Vulnerability.Fix.Versions) > 0 {
				nvdOnlyMatch.Vulnerability.Fix = vulnerability.Fix{
					State: vulnerability.FixStateUnknown,
				}
			}
			cpeMatches = append(cpeMatches, nvdOnlyMatch)
		}
		// since there was no intersection, no need to iterate over it below
		return cpeMatches, nil
	}

	// there is a security feed entry...
	for _, vuln := range feedVulnsForID {
		// ...is there a fixed in entry? (should always be yes)
		if len(vuln.Fix.Versions) == 0 {
			continue
		}

		// ...is the current package vulnerable?
		vulnerable, err := vuln.Constraint.Satisfied(verObj)
		if err != nil {
			return nil, err
		}

		if vulnerable {
			// if there is at least one vulnerable entry, then all CPE record(s) should be surfaced
			// these will be deduped later against the authoritative distro match for the same vuln
			return cpeMatchesForVuln, nil
		}
	}

	return nil, nil
}

func deduplicateMatches(feedMatches, cpeMatches []match.Match) (matches []match.Match) {
	// add additional unique matches from the CPE source that are unique from the feed matches.
	// Suppression is by identity (vulnerability ID or alias) via result.Set.Remove, so a CPE record
	// keyed by a CVE is deduplicated against a feed record (e.g. a CGA) that lists that CVE as an alias.
	unique := newResultSet(matchVulnerabilities(cpeMatches)...).Remove(newResultSet(matchVulnerabilities(feedMatches)...))

	cpeMatchesByID := matchesByID(cpeMatches)
	for id := range unique {
		// add only the cpeMatches which are not already in feedMatches
		matches = append(matches, cpeMatchesByID[id]...)
	}
	return matches
}

func matchesByID(matches []match.Match) map[string][]match.Match {
	var results = make(map[string][]match.Match)
	for _, match := range matches {
		results[match.Vulnerability.ID] = append(results[match.Vulnerability.ID], match)
	}
	return results
}

// vulnSetForPackage collects every security-feed (distro) vulnerability that applies to p, including
// the vulnerabilities recorded against p's upstream/origin packages, and returns them as a result.Set
// keyed by vulnerability ID. Because each result carries the record's RelatedVulnerabilities, the
// returned set supports alias-aware reconciliation: callers can Intersection/Remove CPE (NVD) matches
// against it so that, for example, a CPE match keyed by a CVE is matched to a feed record (e.g. a
// Chainguard CGA) that only lists that CVE as an alias.
func vulnSetForPackage(provider vulnerability.Provider, p pkg.Package) (result.Set, error) {
	// find all feed vulnerabilities for the package and its upstream/origin packages
	vulnerabilities, err := provider.FindVulnerabilities(
		search.ByPackageName(p.Name),
		search.ByDistro(*p.Distro))
	if err != nil {
		return nil, err
	}

	for _, upstreamPkg := range pkg.UpstreamPackages(p) {
		vulnerabilitiesForUpstream, err := provider.FindVulnerabilities(
			search.ByPackageName(upstreamPkg.Name),
			search.ByDistro(*upstreamPkg.Distro))
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vulnerabilitiesForUpstream...)
	}

	// turn into a set for comparisons
	return newResultSet(vulnerabilities...), nil
}

// newResultSet groups vulnerabilities into a result.Set keyed by vulnerability ID. The result.Set
// exposes alias-aware set operations (Remove, Intersection) whose identity is the vulnerability ID
// plus any RelatedVulnerabilities (aliases). This lets the APK matcher suppress and deduplicate
// records that refer to the same underlying vulnerability under different IDs (e.g. a CGA and a CVE).
func newResultSet(vulns ...vulnerability.Vulnerability) result.Set {
	set := result.Set{}
	for _, v := range vulns {
		set[v.ID] = append(set[v.ID], result.Result{
			ID:              v.ID,
			Vulnerabilities: []vulnerability.Vulnerability{v},
		})
	}
	return set
}

// matchVulnerabilities extracts the vulnerability from each match.
func matchVulnerabilities(matches []match.Match) []vulnerability.Vulnerability {
	vulns := make([]vulnerability.Vulnerability, 0, len(matches))
	for _, m := range matches {
		vulns = append(vulns, m.Vulnerability)
	}
	return vulns
}

// findMatchesForPackage for this provider-package pair, find all relevant vulnerability matches
// and ignore filters. This uses the security feed for this distro as well as the upstream nvd data.
func (m *Matcher) findMatchesForPackage(store vulnerability.Provider, p pkg.Package, catalogPkg *pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	// find matches for the given package name and version using the security feed for this distro.
	// APK doesn't use epochs, so pass nil for the config
	distroMatches, distroIgnores, err := internal.MatchPackageByDistro(store, p, catalogPkg, m.Type(), nil)
	if err != nil {
		return nil, nil, err
	}

	// find matches for the given package using the upstream NVD data by CPE
	// TODO: are there other errors that we should handle here that causes this to short circuit
	cpeMatches, cpeIgnores, err := m.cpeMatchesWithoutFixes(store, p)
	if err != nil && !errors.Is(err, internal.ErrEmptyCPEMatch) {
		return nil, nil, err
	}

	var matches []match.Match

	// keep all security feed matches, as this is an authoritative source
	matches = append(matches, distroMatches...)

	// keep only unique CPE matches
	matches = append(matches, deduplicateMatches(distroMatches, cpeMatches)...)

	return matches, append(distroIgnores, cpeIgnores...), nil
}

func (m *Matcher) findMatchesForOriginPackage(store vulnerability.Provider, catalogPkg pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match
	var ignores []match.IgnoreFilter

	for _, indirectPackage := range pkg.UpstreamPackages(catalogPkg) {
		indirectMatches, indirectIgnores, err := m.findMatchesForPackage(store, indirectPackage, &catalogPkg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to find vulnerabilities for apk upstream source package: %w", err)
		}
		matches = append(matches, indirectMatches...)
		ignores = append(ignores, indirectIgnores...)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the indirect package)
	// however, we also want to keep the indirect package around for future reference
	match.ConvertToIndirectMatches(matches, catalogPkg)

	return matches, ignores, nil
}

// NAK entries are those reported as explicitly not vulnerable by the upstream provider,
// for example this entry is present in the v5 database:
// 312891,CVE-2020-7224,openvpn,alpine:distro:alpine:3.10,,< 0,apk,,"[{""id"":""CVE-2020-7224"",""namespace"":""nvd:cpe""}]","[""0""]",fixed,
// which indicates, for the alpine:3.10 distro, package openvpn is not vulnerable to CVE-2020-7224
// we want to report these NAK entries as match.IgnoredMatch, to allow for later processing to create ignore rules
// based on packages which overlap by location, such as a python binary found in addition to the python APK entry --
// we want to NAK this vulnerability for BOTH packages
func (m *Matcher) findNaksForPackage(provider vulnerability.Provider, p pkg.Package) ([]match.IgnoreFilter, error) {
	if p.Distro == nil {
		return nil, nil
	}

	// get all the direct naks
	naks, err := provider.FindVulnerabilities(
		search.ByDistro(*p.Distro),
		search.ByPackageName(p.Name),
		nakConstraint,
	)
	if err != nil {
		return nil, err
	}

	// append all the upstream naks
	for _, upstreamPkg := range pkg.UpstreamPackages(p) {
		upstreamNaks, err := provider.FindVulnerabilities(
			search.ByDistro(*upstreamPkg.Distro),
			search.ByPackageName(upstreamPkg.Name),
			nakConstraint,
		)
		if err != nil {
			return nil, err
		}

		naks = append(naks, upstreamNaks...)
	}

	return internal.OwnershipIgnores(p, "Explicit APK NAK", naks...), nil
}
