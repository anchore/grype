package rpm

import (
	"fmt"

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
	return d != nil && d.Type == distro.AlmaLinux
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
		search.ByDistro(*searchPkg.Distro), // use actual AlmaLinux distro for unaffected lookup
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
	if relatedUnaffectedResults != nil {
		// Merge the related results into the main unaffected results
		for key, results := range relatedUnaffectedResults {
			unaffectedResults[key] = append(unaffectedResults[key], results...)
		}
	}

	// Step 4: Filter disclosures by removing those that have unaffected matches
	filteredDisclosures := filterDisclosuresByUnaffected(disclosures, unaffectedResults, pkgVersion)

	return filteredDisclosures.ToMatches(), nil
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
			search.ByDistro(*searchPkg.Distro),
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

// filterDisclosuresByUnaffected removes disclosures that are marked as unaffected
func filterDisclosuresByUnaffected(disclosures result.Set, unaffectedResults result.Set, pkgVersion *version.Version) result.Set {
	if len(unaffectedResults) == 0 {
		return disclosures
	}

	// Create a map of vulnerability IDs that are unaffected for this version
	unaffectedVulns := make(map[string]bool)

	for _, unaffectedResultList := range unaffectedResults {
		for _, unaffectedResult := range unaffectedResultList {
			for _, vuln := range unaffectedResult.Vulnerabilities {
				// Check if this package version is covered by the unaffected constraint
				if isVersionUnaffected(pkgVersion, vuln.Constraint, vuln.ID) {
					unaffectedVulns[vuln.ID] = true
					log.WithFields("vulnID", vuln.ID, "packageVersion", pkgVersion.Raw, "constraint", vuln.Constraint).Trace("marking vulnerability as unaffected for AlmaLinux")
				}
			}
		}
	}

	// Filter out disclosures for vulnerabilities that are unaffected
	filtered := make(result.Set)
	for key, disclosureList := range disclosures {
		var filteredDisclosures []result.Result

		for _, disclosure := range disclosureList {
			var remainingVulns []vulnerability.Vulnerability

			for _, vuln := range disclosure.Vulnerabilities {
				if !unaffectedVulns[vuln.ID] {
					remainingVulns = append(remainingVulns, vuln)
				} else {
					var packageName string
					if disclosure.Package != nil {
						packageName = disclosure.Package.Name
					}
					log.WithFields("vulnID", vuln.ID, "package", packageName).Debug("filtered out unaffected vulnerability for AlmaLinux")
				}
			}

			// Only include the disclosure if it still has vulnerabilities
			if len(remainingVulns) > 0 {
				filteredDisclosure := disclosure
				filteredDisclosure.Vulnerabilities = remainingVulns
				filteredDisclosures = append(filteredDisclosures, filteredDisclosure)
			}
		}

		// Only add to filtered set if there are remaining disclosures
		if len(filteredDisclosures) > 0 {
			filtered[key] = filteredDisclosures
		}
	}

	return filtered
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
