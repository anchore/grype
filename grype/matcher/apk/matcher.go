package apk

import (
	"errors"
	"fmt"
	"slices"

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
	ignoreReasonDistroFixed = "DistroPackageFixed"
	ignoreReasonExplicitNAK = "Explicit APK NAK"
)

var (
	nakVersionString = version.MustGetConstraint("< 0", version.ApkFormat).String()

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

// Match collects vulnerability matches and ignore filters for an APK package from three sources: the
// authoritative distro security feed, explicit NAK entries, and upstream NVD (CPE) data reconciled
// against the feed. Each source covers the package and its upstream/origin packages.
//
// Everything is reconciled in result.Set space by vulnerability identity -- ID plus aliases -- so
// records naming the same vulnerability under different IDs (a CGA and its CVE, say) are deduplicated
// correctly.
//
// A nil distro is not an error: the distro-feed and NAK paths simply contribute nothing, and the
// package is still matched against NVD.
func (m *Matcher) Match(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	// the distro feed is the authority for an apk. What it considers this version vulnerable to
	// becomes matches; the rest -- already fixed at this version, explicitly unaffected, or NAK'd --
	// is what the other sources reconcile against, and becomes ignores for packages overlapping this
	// one by file.
	vulnerable, allFixed, err := m.distroResults(vp, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find distro matches for apk pkg=%q: %w", p.Name, err)
	}

	// NVD counts only where the feed is silent: a record the feed considers vulnerable is already
	// reported as the authoritative distro match, and one the feed has settled needs no second opinion.
	cpeVulnerable, cpeIgnores, err := m.cpeResults(vp, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find nvd matches for apk pkg=%q: %w", p.Name, err)
	}
	vulnerable = vulnerable.Merge(cpeVulnerable.Remove(vulnerable).Remove(allFixed))

	// NAK entries never produce matches of their own, only ignores
	nakIgnores, err := m.nakIgnores(vp, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find naks for apk pkg=%q: %w", p.Name, err)
	}

	ignores := slices.Concat(
		cpeIgnores,
		nakIgnores,
		internal.OwnershipIgnores(p, ignoreReasonDistroFixed, allFixed.Vulnerabilities()...),
	)

	return vulnerable.ToMatches(), ignores, nil
}

// distroResults searches the authoritative distro feed for the package and each of its upstream/origin
// packages, and partitions what it finds: records this version is vulnerable to, and the rest.
//
// allFixed is broader than its name: alongside records already fixed at this version it holds the ones
// the feed calls unaffected, and apk "< 0" NAKs, which are vulnerable at no version and so land here
// too. That is what makes it the right thing to reconcile other sources against.
func (m *Matcher) distroResults(vp vulnerability.Provider, p pkg.Package) (vulnerable, allFixed result.Set, err error) {
	// APK doesn't use epochs, so pass a nil comparison config.
	vulnerable, allFixed, err = internal.FindResultsByDistro(vp, p, nil, m.Type(), nil)
	if err != nil {
		return nil, nil, err
	}

	for _, upstreamPkg := range pkg.UpstreamPackages(p) {
		upstreamVulnerable, upstreamFixed, err := internal.FindResultsByDistro(vp, upstreamPkg, &p, m.Type(), nil)
		if err != nil {
			return nil, nil, err
		}

		vulnerable = vulnerable.Merge(markIndirect(upstreamVulnerable, p))
		allFixed = allFixed.Merge(upstreamFixed)
	}

	return vulnerable, allFixed, nil
}

// nakIgnores collects explicit NAK ("< 0") entries for the package and its upstreams and returns them
// as ignore filters. NAK entries never produce matches; they only allow later rules to suppress the
// same vulnerability on packages that overlap this one by location.
func (m *Matcher) nakIgnores(vp vulnerability.Provider, p pkg.Package) ([]match.IgnoreFilter, error) {
	if p.Distro == nil {
		return nil, nil
	}

	provider := result.NewProvider(vp, p, m.Type())

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

	return internal.OwnershipIgnores(p, ignoreReasonExplicitNAK, naks.Vulnerabilities()...), nil
}

// cpeResults finds NVD (CPE-indexed) results for the package itself and for each of its
// upstream/origin packages, the latter recorded against the SBOM package. Searching the origin is what
// surfaces, for example, an openssl CVE for a libssl3 APK whose origin is openssl.
func (m *Matcher) cpeResults(provider vulnerability.Provider, p pkg.Package) (result.Set, []match.IgnoreFilter, error) {
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

func (m *Matcher) cpeDisclosures(provider vulnerability.Provider, searchPkg, catalogPkg pkg.Package) (result.Set, []match.IgnoreFilter, error) {
	cpeSet, ignores, err := internal.FindResultsByCPEs(provider, searchPkg, m.Type())
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
		cpeSet = markIndirect(cpeSet, catalogPkg)
	}

	if searchPkg.Distro == nil {
		// no distro feed, so no authority to defer to: NVD's fix is the only information there is
		return cpeSet, ignores, nil
	}

	// NVD cannot know when the distro will ship a fix, and an inferred NVD fix is an upstream release
	// number rather than an apk version, so no record leaves here carrying one (see #2162)
	return stripFixState(cpeSet), ignores, nil
}

// markIndirect records results against the SBOM (catalog) package rather than the upstream package
// they were searched with, and marks their evidence indirect -- the result.Set equivalent of
// match.ConvertToIndirectMatches.
//
// Both halves are needed. The match type is otherwise derived by comparing the searched package name
// against the cataloged one, which cannot tell the two apart when a package is its own origin, so the
// upstream pass says so explicitly.
func markIndirect(s result.Set, catalogPkg pkg.Package) result.Set {
	return s.Map(func(r *result.Result) {
		r.Package = &catalogPkg

		// replace the slice rather than mutate in place: Map shallow-copies results, so the Details
		// backing array is shared with the source set
		details := make([]match.Detail, len(r.Details))
		for i, d := range r.Details {
			if d.Type == match.ExactDirectMatch {
				d.Type = match.ExactIndirectMatch
			}
			details[i] = d
		}
		r.Details = details
	})
}

func stripFixState(s result.Set) result.Set {
	return s.Map(func(r *result.Result) {
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
