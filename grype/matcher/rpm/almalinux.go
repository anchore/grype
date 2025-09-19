package rpm

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// shouldUseAlmaLinuxMatching determines if AlmaLinux-specific matching should be used
func shouldUseAlmaLinuxMatching(d *distro.Distro) bool {
	if d == nil {
		return false
	}
	return d.Type == distro.AlmaLinux
}

// almaLinuxMatches returns matches for the given package with AlmaLinux unaffected filtering applied.
//
// AlmaLinux follows this workflow:
// 1. Use RHEL vulnerability disclosures as the base (similar to RHEL EUS)
// 2. Filter results using AlmaLinux-specific unaffected package records
// 3. Handle source RPM to binary RPM relationships when matching unaffected records
//
// The matching process:
// 1. Find RHEL disclosures that match the package (treating AlmaLinux as RHEL-compatible)
// 2. Find AlmaLinux unaffected packages that apply to this package (including source/binary relationships)
// 3. Remove vulnerabilities that are marked as unaffected in AlmaLinux
func almaLinuxMatches(provider result.Provider, searchPkg pkg.Package) ([]match.Match, error) {
	if strings.HasSuffix(searchPkg.Name, "-debuginfo") || strings.HasSuffix(searchPkg.Name, "-debugsource") {
		return nil, nil // almaloinux explicitly never publishes advisories for RPMs that are only debug material
		// consider these as fixed; otherwise we will have no fixed version for them, and they will be considered
		// to be affected by every CVE that affects their src rpm at any version.
	}
	// Create a RHEL-compatible distro for finding base disclosures
	rhelCompatibleDistro := *searchPkg.Distro
	rhelCompatibleDistro.Type = distro.RedHat // treat as RHEL for disclosure lookup

	pkgVersion := version.New(searchPkg.Version, pkg.VersionFormat(searchPkg))

	// Step 1: Find RHEL disclosures for the package
	disclosures, err := provider.FindResults(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(rhelCompatibleDistro), // look for RHEL disclosures
		internal.OnlyQualifiedPackages(searchPkg),
		internal.OnlyVulnerableVersions(pkgVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch RHEL disclosures for AlmaLinux pkg=%q: %w", searchPkg.Name, err)
	}

	if len(disclosures) == 0 {
		return nil, nil
	}

	// Step 2: Find AlmaLinux unaffected packages that apply to this package
	unaffectedResults, err := provider.FindResults(
		search.ByPackageName(searchPkg.Name),
		search.ByExactDistro(*searchPkg.Distro), // use exact AlmaLinux distro for unaffected lookup (no aliases)
		internal.OnlyQualifiedPackages(searchPkg),
		search.ForUnaffected(),
	)
	if err != nil {
		log.WithFields("error", err, "distro", searchPkg.Distro, "pkg", searchPkg.Name).Debug("failed to fetch AlmaLinux unaffected packages")
		// If we can't get unaffected data, return the original disclosures
		return disclosures.ToMatches(), nil
	}

	// Step 3: Also look for unaffected packages using source/binary RPM relationships and merge
	relatedUnaffectedResults := findRelatedUnaffectedPackages(provider, searchPkg)
	allUnaffectedResults := unaffectedResults.Merge(relatedUnaffectedResults)

	// Step 4: Remove vulnerabilities that are unaffected and update remaining ones with AlmaLinux fix info
	updatedDisclosures := applyAlmaLinuxUnaffectedFiltering(disclosures, allUnaffectedResults, pkgVersion)

	return updatedDisclosures.ToMatches(), nil
}

// findRelatedUnaffectedPackages searches for unaffected packages using source/binary RPM relationships
func findRelatedUnaffectedPackages(provider result.Provider, searchPkg pkg.Package) result.Set {
	allResults := make(result.Set)

	// Get all related package names (source RPM, binary RPM patterns, etc.)
	relatedNames := getRelatedPackageNames(searchPkg)

	for _, relatedName := range relatedNames {
		if relatedName == searchPkg.Name {
			continue // skip the main package name as it's already searched
		}

		// Search for unaffected records using related package names
		relatedResults, err := provider.FindResults(
			search.ByPackageName(relatedName),
			search.ByExactDistro(*searchPkg.Distro), // use exact distro to avoid alias mapping
			internal.OnlyQualifiedPackages(searchPkg),
			search.ForUnaffected(),
		)
		if err != nil {
			log.WithFields("error", err, "relatedName", relatedName, "originalPkg", searchPkg.Name).Debug("failed to fetch related unaffected packages")
			continue
		}

		if len(relatedResults) > 0 {
			log.WithFields("relatedName", relatedName, "originalPkg", searchPkg.Name, "foundUnaffected", len(relatedResults)).Trace("found unaffected records via package relationship")
			// Merge results into our set
			for key, results := range relatedResults {
				allResults[key] = append(allResults[key], results...)
			}
		}
	}

	return allResults
}

// applyAlmaLinuxUnaffectedFiltering applies AlmaLinux unaffected filtering and fix updates
func applyAlmaLinuxUnaffectedFiltering(disclosures result.Set, unaffectedResults result.Set, pkgVersion *version.Version) result.Set {
	if len(unaffectedResults) == 0 {
		return disclosures
	}

	// First, identify vulnerabilities that should be completely filtered out
	toRemove := identifyVulnerabilitiesToRemove(unaffectedResults, pkgVersion)

	// Remove completely unaffected vulnerabilities using result.Set.Remove()
	filtered := disclosures.Remove(toRemove)

	// Then update remaining vulnerabilities with AlmaLinux fix information
	return updateRemainingWithAlmaLinuxFixes(filtered, unaffectedResults, pkgVersion)
}

// identifyVulnerabilitiesToRemove identifies vulnerabilities that should be completely filtered out
func identifyVulnerabilitiesToRemove(unaffectedResults result.Set, pkgVersion *version.Version) result.Set {
	toRemove := make(result.Set)

	for _, unaffectedResultList := range unaffectedResults {
		for _, unaffectedResult := range unaffectedResultList {
			for _, vuln := range unaffectedResult.Vulnerabilities {
				if shouldCompletelyFilter(vuln, pkgVersion) {
					// Create a result entry to mark this vulnerability for removal
					toRemove[vuln.ID] = []result.Result{{
						ID:              vuln.ID,
						Vulnerabilities: []vulnerability.Vulnerability{vuln},
					}}

					// Also mark related vulnerabilities (aliases) for removal
					for _, related := range vuln.RelatedVulnerabilities {
						toRemove[related.ID] = []result.Result{{
							ID:              related.ID,
							Vulnerabilities: []vulnerability.Vulnerability{{Reference: related}},
						}}
					}
				}
			}
		}
	}

	return toRemove
}

// shouldCompletelyFilter determines if a vulnerability should be completely filtered out
func shouldCompletelyFilter(vuln vulnerability.Vulnerability, pkgVersion *version.Version) bool {
	if !isVersionUnaffected(pkgVersion, vuln.Constraint, vuln.ID) {
		return false
	}

	fixVersion := extractFixVersionFromConstraint(vuln.Constraint)
	return shouldFilterVulnerability(vuln.Constraint, fixVersion, pkgVersion)
}

// updateRemainingWithAlmaLinuxFixes updates remaining vulnerabilities with AlmaLinux fix information
func updateRemainingWithAlmaLinuxFixes(disclosures result.Set, unaffectedResults result.Set, pkgVersion *version.Version) result.Set {
	almaLinuxFixes := buildAlmaLinuxFixesMap(unaffectedResults, pkgVersion)

	if len(almaLinuxFixes) == 0 {
		return disclosures
	}

	updated := make(result.Set)
	for key, disclosureList := range disclosures {
		var updatedDisclosures []result.Result

		for _, disclosure := range disclosureList {
			var updatedVulns []vulnerability.Vulnerability

			for _, vuln := range disclosure.Vulnerabilities {
				if almaFix, hasAlmaFix := almaLinuxFixes[vuln.ID]; hasAlmaFix {
					updatedVuln := vuln
					updatedVuln.Fix = almaFix
					updatedVulns = append(updatedVulns, updatedVuln)
				} else {
					updatedVulns = append(updatedVulns, vuln)
				}
			}

			if len(updatedVulns) > 0 {
				updatedDisclosure := disclosure
				updatedDisclosure.Vulnerabilities = updatedVulns
				updatedDisclosures = append(updatedDisclosures, updatedDisclosure)
			}
		}

		if len(updatedDisclosures) > 0 {
			updated[key] = updatedDisclosures
		}
	}

	return updated
}

// buildAlmaLinuxFixesMap builds a map of vulnerability fixes from unaffected results
func buildAlmaLinuxFixesMap(unaffectedResults result.Set, pkgVersion *version.Version) map[string]vulnerability.Fix {
	almaLinuxFixes := make(map[string]vulnerability.Fix)

	for _, unaffectedResultList := range unaffectedResults {
		for _, unaffectedResult := range unaffectedResultList {
			for _, vuln := range unaffectedResult.Vulnerabilities {
				if isVersionUnaffected(pkgVersion, vuln.Constraint, vuln.ID) {
					fixVersion := extractFixVersionFromConstraint(vuln.Constraint)

					// Only update fix info if we're not completely filtering it out
					if !shouldFilterVulnerability(vuln.Constraint, fixVersion, pkgVersion) && fixVersion != "" {
						fix := vulnerability.Fix{
							Versions: []string{fixVersion},
							State:    vulnerability.FixStateFixed,
						}

						almaLinuxFixes[vuln.ID] = fix
						for _, related := range vuln.RelatedVulnerabilities {
							almaLinuxFixes[related.ID] = fix
						}
					}
				}
			}
		}
	}

	return almaLinuxFixes
}

// shouldFilterVulnerability determines if a vulnerability should be completely filtered out
func shouldFilterVulnerability(constraint version.Constraint, fixVersion string, pkgVersion *version.Version) bool {
	if !strings.HasPrefix(constraint.String(), ">= ") || fixVersion == "" {
		return false
	}

	fixVersionParsed := version.New(fixVersion, pkgVersion.Format)
	cmp, err := pkgVersion.Compare(fixVersionParsed)
	return err == nil && cmp >= 0
}

// extractFixVersionFromConstraint extracts a fix version from a version constraint
// e.g., ">= 2.4.48" → "2.4.48", "= 1.2.3-4.el8" → "1.2.3-4.el8"
func extractFixVersionFromConstraint(constraint version.Constraint) string {
	if constraint == nil {
		return ""
	}

	constraintStr := constraint.String()

	// Handle common constraint patterns
	// ">= version" → "version"
	if strings.HasPrefix(constraintStr, ">= ") {
		version := strings.TrimPrefix(constraintStr, ">= ")
		return cleanVersionString(version)
	}

	// "= version" → "version"
	if strings.HasPrefix(constraintStr, "= ") {
		version := strings.TrimPrefix(constraintStr, "= ")
		return cleanVersionString(version)
	}

	// "> version" → we can't determine exact fix version, return empty
	// "< version" → this wouldn't make sense for a fix constraint

	return ""
}

// cleanVersionString removes format suffixes from version strings
// e.g., "2.4.48 (rpm)" → "2.4.48"
func cleanVersionString(versionStr string) string {
	// Remove format suffixes like " (rpm)", " (deb)", etc.
	if idx := strings.Index(versionStr, " ("); idx != -1 {
		return versionStr[:idx]
	}
	return versionStr
}

// isVersionUnaffected checks if a package version is unaffected according to the given constraint
func isVersionUnaffected(v *version.Version, c version.Constraint, id string) bool {
	if c == nil {
		return false
	}

	isUnaffected, err := c.Satisfied(v)
	if err != nil {
		log.WithFields("vulnerability", id, "error", err).Trace("failed to check unaffected constraint")
		return false
	}

	return isUnaffected
}
