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

	// Step 3: Also look for unaffected packages using source/binary RPM relationships
	relatedUnaffectedResults := findRelatedUnaffectedPackages(provider, searchPkg)
	// Merge the related results into the main unaffected results
	for key, results := range relatedUnaffectedResults {
		unaffectedResults[key] = append(unaffectedResults[key], results...)
	}

	// Step 4: Update RHEL disclosures with AlmaLinux-specific fix information
	updatedDisclosures := updateDisclosuresWithAlmaLinuxFixes(disclosures, unaffectedResults, pkgVersion)

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

// updateDisclosuresWithAlmaLinuxFixes filters out vulnerabilities that are unaffected in AlmaLinux
// and updates remaining vulnerabilities with AlmaLinux-specific fix information.
func updateDisclosuresWithAlmaLinuxFixes(disclosures result.Set, unaffectedResults result.Set, pkgVersion *version.Version) result.Set {
	if len(unaffectedResults) == 0 {
		return disclosures
	}

	// Build maps of vulnerability IDs that should be filtered and their fix information
	unaffectedVulns := make(map[string]bool)
	almaLinuxFixes := make(map[string]vulnerability.Fix)

	for _, unaffectedResultList := range unaffectedResults {
		for _, unaffectedResult := range unaffectedResultList {
			for _, vuln := range unaffectedResult.Vulnerabilities {
				// Extract fix version from constraint for potential use
				fixVersion := extractFixVersionFromConstraint(vuln.Constraint)

				// Check if this package version is covered by the unaffected constraint
				if isVersionUnaffected(pkgVersion, vuln.Constraint, vuln.ID) {
					// Check if this constraint indicates the package is at or above the fix version
					// For constraints like ">= X.Y.Z", when our package version equals X.Y.Z, it means we have the fix
					if strings.HasPrefix(vuln.Constraint.String(), ">= ") && fixVersion != "" {
						fixVersionParsed := version.New(fixVersion, pkgVersion.Format)
						cmp, err := pkgVersion.Compare(fixVersionParsed)
						if err == nil && cmp >= 0 {
							// Package version is equal to or greater than the fix version - completely fixed
							unaffectedVulns[vuln.ID] = true
							log.WithFields("vulnID", vuln.ID, "packageVersion", pkgVersion.String(), "fixVersion", fixVersion).Trace("vulnerability filtered: package >= fix version")

							// Also check related vulnerabilities (aliases)
							for _, related := range vuln.RelatedVulnerabilities {
								unaffectedVulns[related.ID] = true
							}
						}
					} else {
						// Other constraint types - update fix info but keep vulnerability
						if fixVersion != "" {
							almaLinuxFixes[vuln.ID] = vulnerability.Fix{
								Versions: []string{fixVersion},
								State:    vulnerability.FixStateFixed,
							}

							// Also update related vulnerabilities (aliases)
							for _, related := range vuln.RelatedVulnerabilities {
								almaLinuxFixes[related.ID] = vulnerability.Fix{
									Versions: []string{fixVersion},
									State:    vulnerability.FixStateFixed,
								}
							}
						}
					}
				}
			}
		}
	}

	// Filter disclosures and update remaining ones with AlmaLinux fix information
	updated := make(result.Set)
	for key, disclosureList := range disclosures {
		var updatedDisclosures []result.Result

		for _, disclosure := range disclosureList {
			var updatedVulns []vulnerability.Vulnerability

			for _, vuln := range disclosure.Vulnerabilities {
				// Check if this vulnerability should be filtered out
				if unaffectedVulns[vuln.ID] {
					continue // Skip this vulnerability - it's unaffected
				}

				// Keep the vulnerability, possibly with updated fix information
				if almaFix, hasAlmaFix := almaLinuxFixes[vuln.ID]; hasAlmaFix {
					// Update with AlmaLinux fix information
					updatedVuln := vuln
					updatedVuln.Fix = almaFix
					updatedVulns = append(updatedVulns, updatedVuln)
				} else {
					// Keep original vulnerability
					updatedVulns = append(updatedVulns, vuln)
				}
			}

			// Include disclosure only if it has remaining vulnerabilities
			if len(updatedVulns) > 0 {
				updatedDisclosure := disclosure
				updatedDisclosure.Vulnerabilities = updatedVulns
				updatedDisclosures = append(updatedDisclosures, updatedDisclosure)
			}
		}

		// Add to updated set only if there are remaining disclosures
		if len(updatedDisclosures) > 0 {
			updated[key] = updatedDisclosures
		}
	}

	return updated
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
