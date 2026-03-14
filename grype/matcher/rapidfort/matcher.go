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
	"github.com/anchore/grype/grype/vulnerability"
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

	return all, nil, nil
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
