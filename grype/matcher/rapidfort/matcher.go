// Package rapidfort provides vulnerability matching for RapidFort-curated images.
// It is activated only when the scanned image is identified as RapidFort-curated
// (via the "maintainer=RapidFort" Docker label). It queries the DB for advisories
// stored under the "rapidfort-<baseOS>" OS name (e.g. "rapidfort-ubuntu"),
// which are never returned for standard distro scans.
package rapidfort

import (
	"fmt"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
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
}

// Matcher matches packages against RapidFort-specific advisories.
// It is only instantiated when the image under scan is detected as RF-curated.
type Matcher struct{}

func NewMatcher() *Matcher {
	return &Matcher{}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	// Only deb (ubuntu) and apk (alpine) are supported RF base distros for now.
	return []syftPkg.Type{syftPkg.DebPkg, syftPkg.ApkPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RapidFortMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	if p.Distro == nil {
		return nil, nil, nil
	}

	// Only match against supported RF-curated base distros (ubuntu → rapidfort-ubuntu, alpine → rapidfort-alpine).
	rfDistroType, ok := rfDistroMap[p.Distro.Type]
	if !ok {
		return nil, nil, nil
	}

	// Build the RF-prefixed distro for DB queries.
	// Intentionally omit the codename (e.g. "jammy") — the RF DB stores no codenames,
	// and passing one would add a codename filter that yields 0 results.
	rfDistro := distro.New(rfDistroType, p.Distro.Version, "")

	var all []match.Match

	// 1. Match by source/upstream package names first (e.g. rf-libxslt1.1 → source rf-libxslt).
	//    RF advisories are tracked against source package names, so this is the primary lookup.
	sourceMatches, err := m.matchUpstreamPackages(store, p, rfDistro)
	if err != nil {
		return nil, nil, fmt.Errorf("rapidfort matcher failed upstream lookup for %q: %w", p.Name, err)
	}
	all = append(all, sourceMatches...)

	// 2. Also match by the binary package name directly (e.g. rf-gnupg2, rsync).
	rfPkg := p
	rfPkg.Distro = rfDistro
	binaryMatches, _, err := internal.MatchPackageByDistro(store, rfPkg, &p, m.Type(), nil)
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

	// 4. Dedup: source and binary lookups can surface the same CVE for the same package.
	return dedupMatches(filtered), nil, nil
}

// matchUpstreamPackages searches the RF DB using the source/upstream package names
// recorded by syft (e.g. binary rf-libxslt1.1 → source rf-libxslt). This mirrors
// exactly how the dpkg matcher resolves source-tracked advisories.
func (m *Matcher) matchUpstreamPackages(store vulnerability.Provider, p pkg.Package, rfDistro *distro.Distro) ([]match.Match, error) {
	var matches []match.Match

	for _, upstream := range pkg.UpstreamPackages(p) {
		upstream.Distro = rfDistro
		found, _, err := internal.MatchPackageByDistro(store, upstream, &p, m.Type(), nil)
		if err != nil {
			return nil, fmt.Errorf("failed RF upstream lookup for source %q: %w", upstream.Name, err)
		}
		matches = append(matches, found...)
	}

	// Mark all upstream-sourced matches as indirect (the artifact is the binary pkg).
	match.ConvertToIndirectMatches(matches, p)
	return matches, nil
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
