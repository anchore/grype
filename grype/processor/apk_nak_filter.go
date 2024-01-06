package processor

import (
	"fmt"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"slices"
)

var _ match.Processor = (*APKNakFilter)(nil)

type APKNakFilter struct {
	distroFalsePositivesByLocationPath map[string][]string
}

func NewAPKNakFilter(s store.Store, d *distro.Distro, pkgs []pkg.Package) (match.Processor, error) {
	enabled := d.Type == distro.Wolfi || d.Type == distro.Chainguard || d.Type == distro.Alpine

	if !enabled {
		return &APKNakFilter{}, nil
	}

	distroFalsePositivesByLocationPath := make(map[string][]string)
	for _, p := range pkgs {
		falsePositivesByLocation, err := getDistroFalsePositivesByLocation(s, d, p)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize APK-nak filter: %w", err)
		}
		for l, vulnIDs := range falsePositivesByLocation {
			distroFalsePositivesByLocationPath[l] = append(distroFalsePositivesByLocationPath[l], vulnIDs...)
		}
	}

	return &APKNakFilter{
		distroFalsePositivesByLocationPath: distroFalsePositivesByLocationPath,
	}, nil
}

func (a APKNakFilter) ProcessMatches(_ pkg.Context, matches match.Matches, ignoredMatches []match.IgnoredMatch) (match.Matches, []match.IgnoredMatch, error) {
	if a.distroFalsePositivesByLocationPath == nil {
		return matches, nil, nil
	}

	matches = filterMatchesUsingDistroFalsePositives(matches, a.distroFalsePositivesByLocationPath)

	return matches, ignoredMatches, nil
}

func getDistroFalsePositivesByLocation(s store.Store, d *distro.Distro, p pkg.Package) (map[string][]string, error) {
	result := make(map[string][]string)

	if data, ok := p.Metadata.(syftPkg.ApkDBEntry); ok {
		entries, err := s.GetByDistro(d, p)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.Constraint.String() == "< 0 (apk)" {
				for _, f := range data.Files {
					result[f.Path] = append(result[f.Path], entry.ID)
				}
			}
		}
	}

	return result, nil
}

// TODO: refactor to use collection
func filterMatchesUsingDistroFalsePositives(ms []match.Match, falsePositivesByLocation map[string][]string) []match.Match {
	var result []match.Match
	for _, m := range ms {
		isFalsePositive := false

		for _, l := range m.Package.Locations.ToSlice() {
			if fpVulnIDs, ok := falsePositivesByLocation[l.RealPath]; ok {
				if slices.Contains(fpVulnIDs, m.Vulnerability.ID) {
					isFalsePositive = true
					break
				}

				for _, relatedVulnerability := range m.Vulnerability.RelatedVulnerabilities {
					if slices.Contains(fpVulnIDs, relatedVulnerability.ID) {
						isFalsePositive = true
						break
					}
				}
			}
		}

		if !isFalsePositive {
			result = append(result, m)
		} else {
			log.WithFields("vuln", m.Vulnerability.ID, "package", displayPackage(m.Package)).Trace("dropping false positive using distro security data")
		}
	}

	return result
}
