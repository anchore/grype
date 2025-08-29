package rpm

import (
	"fmt"
	"strings"

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

type Matcher struct{}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.RpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.RpmMatcher
}

//nolint:funlen
func (m *Matcher) Match(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	provider := result.NewProvider(vp, p, m.Type())

	// Ensure package version always has an explicit epoch for accurate comparison
	searchPkg := p
	addEpochIfApplicable(&searchPkg)

	switch {
	case shouldUseRedhatEUSMatching(searchPkg.Distro):
		matches, err := redhatEUSMatches(provider, searchPkg)
		return matches, nil, err
	default:
		matches, err := m.dualSearchMatches(provider, searchPkg)
		return matches, nil, err
	}
}

// dualSearchMatches implements the new dual-search algorithm that finds vulnerabilities for both
// downstream and upstream packages, then applies resolution logic to determine final matches.
func (m *Matcher) dualSearchMatches(provider result.Provider, searchPkg pkg.Package) ([]match.Match, error) {
	if searchPkg.Distro == nil {
		return nil, nil
	}
	if isUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
		return nil, nil
	}

	var matches []match.Match

	// Phase 1: Check for downstream package vulnerabilities (direct matches)
	downstreamMatches, err := m.findMatches(provider, searchPkg)
	if err != nil {
		return nil, fmt.Errorf("failed to find downstream matches for pkg=%q: %w", searchPkg.Name, err)
	}
	matches = append(matches, downstreamMatches...)

	// Phase 2: Check for downstream fixes to filter out fixed vulnerabilities
	downstreamFixes, err := m.findDownstreamFixes(provider, searchPkg)
	if err != nil {
		return nil, fmt.Errorf("failed to find downstream fixes for pkg=%q: %w", searchPkg.Name, err)
	}

	// Phase 3: Check for upstream package vulnerabilities (indirect matches)
	// But exclude vulnerabilities that are fixed by downstream packages
	upstreamMatches, err := m.findUpstreamMatches(provider, searchPkg)
	if err != nil {
		return nil, fmt.Errorf("failed to find upstream matches for pkg=%q: %w", searchPkg.Name, err)
	}

	// Filter upstream matches based on downstream state
	downstreamVulnIDs := make(map[string]bool)
	downstreamFixedVulnIDs := make(map[string]bool)

	// Track downstream disclosures
	for _, m := range downstreamMatches {
		downstreamVulnIDs[m.Vulnerability.ID] = true
	}

	// Track downstream fixes
	for vulnID := range downstreamFixes {
		downstreamFixedVulnIDs[vulnID] = true
	}

	for _, upstreamMatch := range upstreamMatches {
		vulnID := upstreamMatch.Vulnerability.ID

		// Skip if there's a downstream disclosure (already included as direct match)
		if downstreamVulnIDs[vulnID] {
			continue
		}

		// Skip if there's a downstream fix (vulnerability is resolved)
		if downstreamFixedVulnIDs[vulnID] {
			continue
		}

		// Convert to indirect match type
		for i := range upstreamMatch.Details {
			upstreamMatch.Details[i].Type = match.ExactIndirectMatch
		}
		matches = append(matches, upstreamMatch)
	}

	return matches, nil
}

// findDownstreamFixes finds all fixes available for the downstream package
func (m *Matcher) findDownstreamFixes(provider result.Provider, searchPkg pkg.Package) (result.Set, error) {
	allResults, err := provider.FindResults(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		internal.OnlyQualifiedPackages(searchPkg),
	)
	if err != nil {
		return result.Set{}, err
	}

	pkgVersion := version.New(searchPkg.Version, pkg.VersionFormat(searchPkg))

	// Filter to only explicit fixes that apply to our package version
	return allResults.Filter(search.ByFixedVersion(*pkgVersion)), nil
}

// findUpstreamMatches finds vulnerability matches for all upstream packages
func (m *Matcher) findUpstreamMatches(provider result.Provider, searchPkg pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	for _, upstreamPkg := range pkg.UpstreamPackages(searchPkg) {
		upstreamMatches, err := m.findMatches(provider, upstreamPkg)
		if err != nil {
			return nil, fmt.Errorf("failed to find matches for upstream package %q: %w", upstreamPkg.Name, err)
		}
		matches = append(matches, upstreamMatches...)
	}

	return matches, nil
}

func (m *Matcher) findMatches(provider result.Provider, searchPkg pkg.Package) ([]match.Match, error) {
	if searchPkg.Distro == nil {
		return nil, nil
	}
	if isUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
		return nil, nil
	}

	switch {
	case shouldUseRedhatEUSMatching(searchPkg.Distro):
		return redhatEUSMatches(provider, searchPkg)
	default:
		return standardMatches(provider, searchPkg)
	}
}

func standardMatches(provider result.Provider, searchPkg pkg.Package) ([]match.Match, error) {
	disclosures, err := provider.FindResults(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		internal.OnlyQualifiedPackages(searchPkg),
		internal.OnlyVulnerableVersions(version.New(searchPkg.Version, pkg.VersionFormat(searchPkg))),
	)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch disclosures for distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	return disclosures.ToMatches(), nil
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
