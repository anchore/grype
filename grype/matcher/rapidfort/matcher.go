// Package rapidfort provides vulnerability matching for RapidFort-curated images.
// It is activated only when the scanned image is identified as RapidFort-curated
// (via the "maintainer=RapidFort" Docker label). It queries the DB for advisories
// stored under the "rapidfort-<baseOS>" OS name (e.g. "rapidfort-ubuntu"),
// which are never returned for standard distro scans.
package rapidfort

import (
	"fmt"
	"regexp"
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

// rfDistroMap maps a detected base OS type to its RF-prefixed counterpart in the DB.
// Extend this (plus getPackageType in v6 transform.go) when RF curates a new base distro.
var rfDistroMap = map[distro.Type]distro.Type{
	distro.Ubuntu: distro.RapidFortUbuntu,
	distro.Alpine: distro.RapidFortAlpine,
	distro.RedHat: distro.RapidFortRedHat,
}

var (
	fedoraReleasePattern = regexp.MustCompile(`\.fc\d+(?:[._-].*)?$`)
	rhelReleasePattern   = regexp.MustCompile(`\.el(\d+)`)
	rfReleasePattern     = regexp.MustCompile(`\.rf(?:[._-].*)?$`)
)

const (
	reasonNoReleaseIdentifier       = "no release identifier on vulnerability"
	reasonCannotDeriveReleaseID     = "unable to derive rpm release identifier and no el release identifier on vulnerability"
	reasonReleaseIdentifierMismatch = "package release identifier did not match vulnerability"
)

// Matcher matches packages against RapidFort-specific advisories.
// It is only instantiated when the image under scan is detected as RF-curated.
type Matcher struct{}

func NewMatcher() *Matcher {
	return &Matcher{}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.DebPkg, syftPkg.ApkPkg, syftPkg.RpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RapidFortMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	if p.Distro == nil {
		return nil, nil, nil
	}

	// Only match against supported RF-curated base distros (ubuntu/alpine/redhat).
	rfDistroType, ok := rfDistroMap[p.Distro.Type]
	if !ok {
		return nil, nil, nil
	}

	// Build the RF-prefixed distro for DB queries.
	// Intentionally omit the codename (e.g. "jammy") — the RF DB stores no codenames,
	// and passing one would add a codename filter that yields 0 results.
	rfDistro := distro.New(rfDistroType, rapidfortDistroVersion(*p.Distro, rfDistroType), "")
	log.WithFields(
		"package", p.Name,
		"version", p.Version,
		"sourceDistro", p.Distro.String(),
		"rapidfortDistro", rfDistro.String(),
	).Debug("rapidfort matcher: remapped distro for RapidFort query")

	var all []match.Match

	// 1. Match by source/upstream package names first, when syft populated Upstreams (same idea as
	//    dpkg/rpm matchers): e.g. Debian binary → source, or RPM subpackage → source name from
	//    SourceRPM metadata. If Upstreams is empty, this step is a no-op.
	sourceMatches, err := m.matchUpstreamPackages(store, p, rfDistro)
	if err != nil {
		return nil, nil, fmt.Errorf("rapidfort matcher failed upstream lookup for %q: %w", p.Name, err)
	}
	all = append(all, sourceMatches...)

	// 2. Direct lookup by installed package name (covers RF-prefixed binaries and advisories
	//    keyed on the subpackage/binary name rather than the source).
	rfPkg := p
	rfPkg.Distro = rfDistro
	binaryMatches, err := m.matchPackageByDistro(store, rfPkg, &p)
	if err != nil {
		return nil, nil, fmt.Errorf("rapidfort matcher failed binary lookup for %q: %w", p.Name, err)
	}
	all = append(all, binaryMatches...)

	// 3. Post-filter: suppress any match where the installed version is already at or
	//    beyond the recorded fix version.  This is an explicit safety net — well-formed
	//    RF advisories use strict "< fixVersion" constraints so the DB query already
	//    excludes fixed packages, but this guards against edge cases (e.g. advisory
	//    has only an "introduced" event and was later patched without updating the DB).
	//
	//    Priority: fix-version check first, range constraint second.
	format := pkg.VersionFormat(p)
	filtered := filterAlreadyFixed(all, p.Version, format)

	// 4. Dedup: upstream and direct lookups can surface the same CVE for the same package.
	return dedupMatches(filtered), nil, nil
}

func rapidfortDistroVersion(baseDistro distro.Distro, rfDistroType distro.Type) string {
	if rfDistroType == distro.RapidFortRedHat && baseDistro.MajorVersion() != "" {
		return baseDistro.MajorVersion()
	}
	return baseDistro.Version
}

// matchUpstreamPackages searches the RF DB using pkg.UpstreamPackages(p) — names from syft’s
// Upstreams field (Debian source packages, RPM source names derived from SourceRPM, etc.).
// Works for DebPkg, ApkPkg, and RpmPkg whenever the catalog includes upstream metadata.
func (m *Matcher) matchUpstreamPackages(store vulnerability.Provider, p pkg.Package, rfDistro *distro.Distro) ([]match.Match, error) {
	var matches []match.Match

	for _, upstream := range pkg.UpstreamPackages(p) {
		upstream.Distro = rfDistro
		found, err := m.matchPackageByDistro(store, upstream, &p)
		if err != nil {
			return nil, fmt.Errorf("failed RF upstream lookup for source %q: %w", upstream.Name, err)
		}
		matches = append(matches, found...)
	}

	// Mark all upstream-sourced matches as indirect (the artifact is the binary pkg).
	match.ConvertToIndirectMatches(matches, p)
	return matches, nil
}

func (m *Matcher) matchPackageByDistro(store vulnerability.Provider, searchPkg pkg.Package, catalogPkg *pkg.Package) ([]match.Match, error) {
	if searchPkg.Distro == nil {
		return nil, nil
	}

	pkgVersion := version.New(searchPkg.Version, pkg.VersionFormat(searchPkg))
	criteria := []vulnerability.Criteria{
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		internal.OnlyQualifiedPackages(searchPkg),
		internal.OnlyVulnerableVersions(pkgVersion),
	}

	if searchPkg.Distro.Type == distro.RapidFortRedHat {
		criteria = append(criteria, byRPMReleaseIdentifier(searchPkg))
	}

	vulns, err := store.FindVulnerabilities(criteria...)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	log.WithFields(
		"package", searchPkg.Name,
		"version", searchPkg.Version,
		"distro", searchPkg.Distro.String(),
		"matches", len(vulns),
	).Debug("rapidfort matcher: fetched vulnerabilities for package")

	var matches []match.Match
	for _, vuln := range vulns {
		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       matchPackage(searchPkg, catalogPkg),
			Details:       distroMatchDetails(m.Type(), searchPkg, catalogPkg, vuln),
		})
	}

	return matches, nil
}

func byRPMReleaseIdentifier(p pkg.Package) vulnerability.Criteria {
	return search.ByFunc(func(vuln vulnerability.Vulnerability) (bool, string, error) {
		expected := installedReleaseIdentifier(p)
		if expected == "" {
			for _, advisory := range vuln.Advisories {
				id := advisoryID(advisory)
				if strings.HasPrefix(id, "release-identifier:el") {
					return true, "", nil
				}
			}
			return false, reasonCannotDeriveReleaseID, nil
		}

		found := false
		for _, advisory := range vuln.Advisories {
			id := advisoryID(advisory)
			if !strings.HasPrefix(id, "release-identifier:") {
				continue
			}
			found = true
			if strings.TrimPrefix(id, "release-identifier:") == expected {
				return true, "", nil
			}
		}

		if !found {
			return false, reasonNoReleaseIdentifier, nil
		}

		return false, reasonReleaseIdentifierMismatch, nil
	})
}

func advisoryID(advisory vulnerability.Advisory) string {
	return strings.ToLower(strings.TrimSpace(advisory.ID))
}

func installedReleaseIdentifier(p pkg.Package) string {
	version := strings.ToLower(strings.TrimSpace(p.Version))

	if id := fedoraReleaseID(p, version); id != "" {
		return id
	}
	if id := rfReleaseID(p, version); id != "" {
		return id
	}
	if id := rhelReleaseID(p, version); id != "" {
		return id
	}
	if id := rfNameReleaseID(p); id != "" {
		return id
	}

	return ""
}

func fedoraReleaseID(p pkg.Package, version string) string {
	if !fedoraReleasePattern.MatchString(version) {
		return ""
	}

	idx := strings.LastIndex(version, ".fc")
	if idx < 0 {
		return ""
	}

	id := version[idx+1:]
	return id
}

func rfReleaseID(p pkg.Package, version string) string {
	if !rfReleasePattern.MatchString(version) {
		return ""
	}

	return "rf"
}

func rhelReleaseID(p pkg.Package, version string) string {
	if !rhelReleasePattern.MatchString(version) {
		return ""
	}

	match := rhelReleasePattern.FindStringSubmatch(version)
	if len(match) != 2 {
		return ""
	}
	id := "el" + match[1]
	return id
}

func rfNameReleaseID(p pkg.Package) string {
	if !strings.HasPrefix(strings.ToLower(p.Name), "rf-") {
		return ""
	}
	return "rf"
}

func matchPackage(searchPkg pkg.Package, catalogPkg *pkg.Package) pkg.Package {
	if catalogPkg != nil {
		return *catalogPkg
	}
	return searchPkg
}

func distroMatchDetails(upstreamMatcher match.MatcherType, searchPkg pkg.Package, catalogPkg *pkg.Package, vuln vulnerability.Vulnerability) []match.Detail {
	ty := match.ExactIndirectMatch
	if catalogPkg == nil {
		ty = match.ExactDirectMatch
	}

	return []match.Detail{
		{
			Type:    ty,
			Matcher: upstreamMatcher,
			SearchedBy: match.DistroParameters{
				Distro: match.DistroIdentification{
					Type:    searchPkg.Distro.Type.String(),
					Version: searchPkg.Distro.Version,
				},
				Package: match.PackageParameter{
					Name:    searchPkg.Name,
					Version: searchPkg.Version,
				},
				Namespace: vuln.Namespace,
			},
			Found: match.DistroResult{
				VulnerabilityID:   vuln.ID,
				VersionConstraint: vuln.Constraint.String(),
			},
			Confidence: 1.0,
		},
	}
}

// filterAlreadyFixed removes matches where the installed version exactly equals
// a recorded fix version, meaning the package has been patched.
//
// Logic (in priority order):
//  1. If Fix.State == FixStateFixed AND installedVersion == fixVersion → suppress.
//  2. Otherwise the range constraint (already evaluated by FindVulnerabilities) decides.
func filterAlreadyFixed(matches []match.Match, installedVer string, format version.Format) []match.Match {
	installed := version.New(installedVer, format)
	var out []match.Match
	for _, m := range matches {
		fix := m.Vulnerability.Fix
		if fix.State == vulnerability.FixStateFixed {
			suppressed := false
			for _, fixVer := range fix.Versions {
				if fixVer == "" || fixVer == "None" {
					continue
				}
				// cmp = fixVersion.Compare(installed): 0 means installed == fixVersion
				cmp, err := version.New(fixVer, format).Compare(installed)
				if err != nil {
					log.WithFields("pkg", installedVer, "fixVersion", fixVer, "err", err).
						Trace("rapidfort: could not compare fix version, keeping match")
					continue
				}
				if cmp == 0 {
					// installed version equals the fix — package is patched
					log.WithFields("vuln", m.Vulnerability.ID, "pkg", installedVer, "fixVersion", fixVer).
						Trace("rapidfort: suppressing match — installed version == fix version")
					suppressed = true
					break
				}
			}
			if suppressed {
				vulnerability.LogDropped(m.Vulnerability.ID, "rapidfort-matcher",
					"installed version equals fix version", installedVer)
				continue
			}
		}
		out = append(out, m)
	}
	return out
}

// dedupMatches removes duplicate matches with the same vulnerability ID.
// Source and binary package lookups can surface the same CVE for the same package.
func dedupMatches(matches []match.Match) []match.Match {
	seen := make(map[string]struct{}, len(matches))
	out := make([]match.Match, 0, len(matches))
	for _, m := range matches {
		if _, ok := seen[m.Vulnerability.ID]; ok {
			continue
		}
		seen[m.Vulnerability.ID] = struct{}{}
		out = append(out, m)
	}
	return out
}
