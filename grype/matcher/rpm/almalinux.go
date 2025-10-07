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

// almaLinuxMatchesWithUpstreams handles AlmaLinux matching for both the binary package and its upstream packages
// This function orchestrates the complete AlmaLinux matching flow:
// 1. Search for RHEL disclosures for the binary package
// 2. Search for RHEL disclosures for all upstream (source) packages
// 3. Search for AlmaLinux unaffected records for the binary package and related packages
// 4. Apply filtering logic to determine which disclosures are still vulnerable on AlmaLinux
func almaLinuxMatchesWithUpstreams(provider result.Provider, binaryPkg pkg.Package) ([]match.Match, error) {
	if strings.HasSuffix(binaryPkg.Name, "-debuginfo") || strings.HasSuffix(binaryPkg.Name, "-debugsource") {
		return nil, nil // almalinux explicitly never publishes advisories for RPMs that are only debug material
	}

	// Create a RHEL-compatible distro for finding base disclosures
	rhelCompatibleDistro := *binaryPkg.Distro
	rhelCompatibleDistro.Type = distro.RedHat // treat as RHEL for disclosure lookup

	pkgVersion := version.New(binaryPkg.Version, pkg.VersionFormat(binaryPkg))

	// Step 1: Find RHEL disclosures for the binary package (direct match)
	binaryDisclosures, err := provider.FindResults(
		search.ByPackageName(binaryPkg.Name),
		search.ByDistro(rhelCompatibleDistro),
		internal.OnlyQualifiedPackages(binaryPkg),
		internal.OnlyVulnerableVersions(pkgVersion),
		internal.OnlyAffectedVulnerabilities(), // exclude unaffected records
	)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch RHEL disclosures for AlmaLinux binary pkg=%q: %w", binaryPkg.Name, err)
	}

	// Step 2: Find RHEL disclosures for upstream (source) packages (indirect match)
	upstreamDisclosures := result.Set{}
	for _, upstreamPkg := range pkg.UpstreamPackages(binaryPkg) {
		upstreamResults, err := provider.FindResults(
			search.ByPackageName(upstreamPkg.Name),
			search.ByDistro(rhelCompatibleDistro),
			internal.OnlyQualifiedPackages(upstreamPkg),
			internal.OnlyVulnerableVersions(pkgVersion),
			internal.OnlyAffectedVulnerabilities(), // exclude unaffected records
		)
		if err != nil {
			log.WithFields("error", err, "upstreamPkg", upstreamPkg.Name, "binaryPkg", binaryPkg.Name).Debug("failed to fetch RHEL disclosures for upstream package")
			continue
		}
		upstreamDisclosures = upstreamDisclosures.Merge(upstreamResults)
	}

	// Merge all disclosures (binary + upstream)
	allDisclosures := binaryDisclosures.Merge(upstreamDisclosures)

	if len(allDisclosures) == 0 {
		return nil, nil
	}

	// Step 3: Find AlmaLinux unaffected records for the binary package
	directUnaffected, err := provider.FindResults(
		search.ByPackageName(binaryPkg.Name),
		search.ByExactDistro(*binaryPkg.Distro), // use exact AlmaLinux distro for unaffected lookup (no aliases)
		internal.OnlyQualifiedPackages(binaryPkg),
		search.ForUnaffected(),
	)
	if err != nil {
		log.WithFields("error", err, "distro", binaryPkg.Distro, "pkg", binaryPkg.Name).Debug("failed to fetch AlmaLinux unaffected packages")
		// If we can't get unaffected data, return the original disclosures
		return allDisclosures.ToMatches(), nil
	}

	// Step 4: Find AlmaLinux unaffected records for related packages (source/binary relationships)
	// This handles cases where AlmaLinux publishes unaffected records for binary packages (e.g., python3-tkinter)
	// but the disclosure is for the source package (e.g., python3)
	relatedUnaffected := findRelatedUnaffectedPackages(provider, binaryPkg)

	// Merge all unaffected results
	allUnaffected := directUnaffected.Merge(relatedUnaffected)

	// Step 5: Apply filtering logic: if disclosure exists and no fix applies, the package is vulnerable
	updatedDisclosures := applyAlmaLinuxUnaffectedFiltering(allDisclosures, allUnaffected, pkgVersion)

	return updatedDisclosures.ToMatches(), nil
}

// almaLinuxMatches is a compatibility wrapper for tests that calls the new implementation
// Deprecated: This function is kept for backward compatibility with existing tests
// New code should use almaLinuxMatchesWithUpstreams instead
func almaLinuxMatches(provider result.Provider, searchPkg pkg.Package) ([]match.Match, error) {
	return almaLinuxMatchesWithUpstreams(provider, searchPkg)
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

	log.WithFields("almaLinuxFixesCount", len(almaLinuxFixes), "unaffectedResultsCount", len(unaffectedResults)).Debug("built AlmaLinux fixes map")

	if len(almaLinuxFixes) == 0 {
		log.Debug("no AlmaLinux fixes found, returning original disclosures")
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
// This extracts fix information from AlmaLinux unaffected records and makes it available
// for both vulnerable packages (to show the fix version) and unaffected packages (to filter them out)
func buildAlmaLinuxFixesMap(unaffectedResults result.Set, pkgVersion *version.Version) map[string]vulnerability.Fix {
	almaLinuxFixes := make(map[string]vulnerability.Fix)

	for _, unaffectedResultList := range unaffectedResults {
		for _, unaffectedResult := range unaffectedResultList {
			for _, vuln := range unaffectedResult.Vulnerabilities {
				constraintStr := ""
				if vuln.Constraint != nil {
					constraintStr = vuln.Constraint.String()
				}

				fixVersion := extractFixVersionFromConstraint(vuln.Constraint)
				if fixVersion == "" {
					continue
				}

				// Determine if we should add this fix based on the constraint type
				shouldAddFix := false

				if strings.HasPrefix(constraintStr, ">= ") {
					// For ">= X" constraints: always add fix
					// - If package >= X: will be filtered completely (handled in shouldCompletelyFilter)
					// - If package < X: package is vulnerable, X is the fix version
					shouldAddFix = true
				} else if strings.HasPrefix(constraintStr, "= ") {
					// For "= X" constraints: only add fix if package matches exactly
					// This handles cases where AlmaLinux marks specific versions as fixed
					shouldAddFix = isVersionUnaffected(pkgVersion, vuln.Constraint, vuln.ID)
				}

				if !shouldAddFix {
					continue
				}

				// Create fix from AlmaLinux unaffected record
				fix := vulnerability.Fix{
					Versions: []string{fixVersion},
					State:    vulnerability.FixStateFixed,
				}

				// Add fix for the vulnerability itself
				almaLinuxFixes[vuln.ID] = fix

				// Also add fix for all related vulnerabilities (e.g., CVEs that ALSA fixes)
				for _, related := range vuln.RelatedVulnerabilities {
					almaLinuxFixes[related.ID] = fix
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
