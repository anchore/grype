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
	syftPkg "github.com/anchore/syft/syft/pkg"
)

const (
	// IgnoreReasonDistroFixed - the distro feed marks the package as already fixed at or past the
	// package's version, so an overlapping package (e.g. a binary owned by the APK) should ignore it.
	IgnoreReasonDistroFixed = "DistroPackageFixed"

	// IgnoreReasonExplicitNAK - the distro source explicitly reports the package as not affected
	// (a "< 0" NAK entry). Kept as an ignore so later rules can suppress the same vulnerability on
	// packages that overlap this one by location.
	IgnoreReasonExplicitNAK = "Explicit APK NAK"
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

// Match collects vulnerability matches and ignore filters for an APK package from three sources:
// the authoritative distro security feed (for the package and its upstream/origin packages), the
// upstream NVD (CPE) data reconciled against that feed, and explicit NAK entries. Everything is
// reconciled in result.Set space by vulnerability identity (ID plus aliases) so that records
// referring to the same underlying vulnerability under different IDs (e.g. a CGA and a CVE) are
// deduplicated correctly.
func (m *Matcher) Match(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	// A nil distro is not an error: the distro-feed and NAK paths simply contribute nothing, and the
	// package is still matched against the upstream NVD (CPE) data below.
	provider := result.NewProvider(vp, p, m.Type())

	var allIgnores []match.IgnoreFilter

	// authoritative distro-feed matches for the package itself
	directDisclosures, directIgnores, err := m.directDistroMatches(provider, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find direct distro matches for apk pkg=%q: %w", p.Name, err)
	}
	allIgnores = append(allIgnores, directIgnores...)

	// authoritative distro-feed matches via the package's upstream/origin packages (indirect)
	indirectDisclosures, indirectIgnores, err := m.indirectDistroMatches(provider, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find indirect distro matches for apk pkg=%q: %w", p.Name, err)
	}
	allIgnores = append(allIgnores, indirectIgnores...)

	allDisclosures := directDisclosures.Merge(indirectDisclosures)

	// NAK entries contribute only ignore rules (explicit "not affected" records)
	nakIgnores, err := m.nakMatches(provider, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find naks for apk pkg=%q: %w", p.Name, err)
	}
	allIgnores = append(allIgnores, nakIgnores...)

	// upstream NVD (CPE) matches (the hard part) reconciled against the distro feed by identity;
	// the distro feed is authoritative, so CPE records overlapping a distro match are dropped.
	upstreamDisclosures, upstreamIgnores, err := m.upstreamMatches(provider, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find upstream nvd matches for apk pkg=%q: %w", p.Name, err)
	}
	allIgnores = append(allIgnores, upstreamIgnores...)
	// only add upstream disclosures that do not overlap the distro disclosures.
	allDisclosures = allDisclosures.Merge(upstreamDisclosures.Remove(allDisclosures))

	return allDisclosures.ToMatches(), allIgnores, nil
}

// directDistroMatches finds the authoritative distro-feed disclosures for the package itself, and
// returns the vulnerabilities the feed reports as already fixed as distro-fixed ignore filters.
func (m *Matcher) directDistroMatches(provider result.Provider, p pkg.Package) (result.Set, []match.IgnoreFilter, error) {
	// APK doesn't use epochs, so pass a nil comparison config.
	vulnerable, fixed, err := internal.FindResultsByDistro(provider.VulnerabilityProvider(), p, nil, m.Type(), nil)
	if err != nil {
		return nil, nil, err
	}

	ignores := internal.OwnershipIgnores(p, IgnoreReasonDistroFixed, fixed.Vulnerabilities()...)
	return vulnerable, ignores, nil
}

// indirectDistroMatches finds distro-feed disclosures via the package's upstream/origin packages,
// recorded as indirect matches against the SBOM package p. Fixed vulnerabilities become distro-fixed
// ignore filters attributed to p (the SBOM package carries the file-ownership metadata, the synthetic
// upstream does not).
func (m *Matcher) indirectDistroMatches(provider result.Provider, p pkg.Package) (result.Set, []match.IgnoreFilter, error) {
	var ignores []match.IgnoreFilter
	disclosures := result.Set{}

	for _, upstreamPkg := range pkg.UpstreamPackages(p) {
		vulnerable, fixed, err := internal.FindResultsByDistro(provider.VulnerabilityProvider(), upstreamPkg, &p, m.Type(), nil)
		if err != nil {
			return nil, nil, err
		}

		// these came from an upstream search, so record them as indirect matches — regardless of whether
		// the upstream name happens to equal p's (the redundant self-upstream case, where the underlying
		// name-based match-type detection would otherwise mark them direct).
		vulnerable = vulnerable.Map(func(r *result.Result) {
			details := make([]match.Detail, len(r.Details))
			for i, d := range r.Details {
				if d.Type == match.ExactDirectMatch {
					d.Type = match.ExactIndirectMatch
				}
				details[i] = d
			}
			r.Details = details
		})

		ignores = append(ignores, internal.OwnershipIgnores(p, IgnoreReasonDistroFixed, fixed.Vulnerabilities()...)...)
		disclosures = disclosures.Merge(vulnerable)
	}

	return disclosures, ignores, nil
}

// nakMatches collects explicit NAK ("< 0") entries for the package and its upstreams and returns
// them as ignore filters. NAK entries never produce matches; they only allow later rules to
// suppress the same vulnerability on packages that overlap this one by location.
func (m *Matcher) nakMatches(provider result.Provider, p pkg.Package) ([]match.IgnoreFilter, error) {
	if p.Distro == nil {
		return nil, nil
	}

	naks, err := provider.FindResults(
		search.ByDistro(*p.Distro),
		search.ByPackageName(p.Name),
		nakConstraint,
	)
	if err != nil {
		return nil, err
	}

	for _, upstreamPkg := range pkg.UpstreamPackages(p) {
		upstreamNaks, err := provider.FindResults(
			search.ByDistro(*upstreamPkg.Distro),
			search.ByPackageName(upstreamPkg.Name),
			nakConstraint,
		)
		if err != nil {
			return nil, err
		}
		naks = naks.Merge(upstreamNaks)
	}

	return internal.OwnershipIgnores(p, IgnoreReasonExplicitNAK, naks.Vulnerabilities()...), nil
}

// upstreamMatches finds NVD (CPE-indexed) matches for the package itself and for each of its
// upstream/origin packages (the latter recorded as indirect matches against the SBOM package),
// reconciled against the distro feed. Upstream CPE matching is what surfaces, for example, an
// openssl CVE for a libssl3 APK whose origin is openssl.
func (m *Matcher) upstreamMatches(provider result.Provider, p pkg.Package) (result.Set, []match.IgnoreFilter, error) {
	disclosures, ignores, err := m.cpeDisclosures(provider, p, p)
	if err != nil {
		return nil, nil, err
	}

	for _, upstreamPkg := range pkg.UpstreamPackages(p) {
		upstreamDisclosures, upstreamIgnores, err := m.cpeDisclosures(provider, upstreamPkg, p)
		if err != nil {
			return nil, nil, err
		}
		disclosures = disclosures.Merge(upstreamDisclosures)
		ignores = append(ignores, upstreamIgnores...)
	}

	return disclosures, ignores, nil
}

// cpeDisclosures finds NVD (CPE) results for searchPkg and reconciles them against the distro feed by
// identity (ID or alias). The distro feed is authoritative for fix state, so:
//   - a record the feed knows nothing about is kept, but its NVD fix state is cleared (NVD can't know
//     when the distro will fix things);
//   - a record the feed still considers vulnerable at this version is kept (and later deduped against
//     the authoritative distro match by Match);
//   - a record the feed considers fixed is dropped.
//
// When searchPkg is an upstream/origin package (its name differs from the SBOM catalogPkg) the results
// are recorded against catalogPkg, which carries the location metadata.
func (m *Matcher) cpeDisclosures(provider result.Provider, searchPkg, catalogPkg pkg.Package) (result.Set, []match.IgnoreFilter, error) {
	// APK-specific CPE preprocessing (e.g. alpineCPEComparableVersion) lives in FindResultsByCPEs.
	// A package with no CPEs is not an error here; it simply contributes no NVD matches.
	cpeSet, ignores, err := internal.FindResultsByCPEs(provider.VulnerabilityProvider(), searchPkg, m.Type())
	if err != nil {
		if !errors.Is(err, internal.ErrEmptyCPEMatch) {
			return nil, nil, err
		}
		return result.Set{}, ignores, nil
	}

	if len(cpeSet) == 0 {
		return cpeSet, ignores, nil
	}

	if searchPkg.Name != catalogPkg.Name {
		cpeSet = indirectResults(cpeSet, catalogPkg)
	}

	if searchPkg.Distro == nil {
		// no distro feed to reconcile against; surface the raw NVD matches (as main did for nil distro)
		return cpeSet, ignores, nil
	}

	// gather every distro-feed entry for searchPkg and its upstreams (unfiltered by version) so CPE
	// records can be reconciled against the feed by identity.
	feed, err := feedSet(provider, searchPkg)
	if err != nil {
		return nil, nil, err
	}

	// records the feed knows nothing about: keep them, but clear the (untrustworthy) NVD fix state
	notInFeed := stripFixState(cpeSet.Remove(feed))

	// records the feed still considers vulnerable at this version: keep them as-is. These usually
	// duplicate an authoritative distro match and are dropped by Match's Remove(allDisclosures).
	// Edge case: it preserves a ForUnaffected-suppressed-but-version-vulnerable CPE record — one the
	// feed reports vulnerable at this version but that the distro path removed via a ForUnaffected
	// record, so it is not in allDisclosures for Match to dedup against.
	verObj := version.New(searchPkg.Version, pkg.VersionFormat(searchPkg))
	feedVulnerable := feed.Filter(internal.OnlyVulnerableVersions(verObj))
	stillVulnerable := cpeSet.Intersection(feedVulnerable)

	return notInFeed.Merge(stillVulnerable), ignores, nil
}

// feedSet gathers every distro-feed entry for the package and its upstream/origin packages, unfiltered
// by version, so callers can reconcile other sources against the feed by identity.
func feedSet(provider result.Provider, p pkg.Package) (result.Set, error) {
	feed, err := provider.FindResults(
		search.ByPackageName(p.Name),
		search.ByDistro(*p.Distro),
	)
	if err != nil {
		return nil, err
	}

	for _, upstreamPkg := range pkg.UpstreamPackages(p) {
		u, err := provider.FindResults(
			search.ByPackageName(upstreamPkg.Name),
			search.ByDistro(*upstreamPkg.Distro),
		)
		if err != nil {
			return nil, err
		}
		feed = feed.Merge(u)
	}

	return feed, nil
}

// indirectResults records the results against the SBOM (catalog) package rather than the upstream
// package they were searched with (mirrors match.ConvertToIndirectMatches for the result.Set model).
func indirectResults(s result.Set, catalogPkg pkg.Package) result.Set {
	return s.Map(func(r *result.Result) {
		r.Package = &catalogPkg
	})
}

// stripFixState clears the fix information on any vulnerability that carries fix versions, marking it
// unknown. Used for NVD-only records where the distro fix state is not knowable from NVD.
func stripFixState(s result.Set) result.Set {
	return s.Map(func(r *result.Result) {
		// replace the slice rather than mutate in place: Map shallow-copies results, so the
		// Vulnerabilities backing array is shared with the source set.
		vulns := make([]vulnerability.Vulnerability, len(r.Vulnerabilities))
		for i, v := range r.Vulnerabilities {
			if len(v.Fix.Versions) > 0 {
				v.Fix = vulnerability.Fix{State: vulnerability.FixStateUnknown}
			}
			vulns[i] = v
		}
		r.Vulnerabilities = vulns
	})
}
