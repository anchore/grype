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
	// Note: We do NOT add epochs to upstream package versions because sourceRPMs often omit epochs
	// even when the source package has a non-zero epoch. See the comment in matchUpstreamPackages
	// in matcher.go for the full explanation of why this is necessary.
	upstreamDisclosures := result.Set{}
	for _, upstreamPkg := range pkg.UpstreamPackages(binaryPkg) {
		// Create a version object from the upstream package WITHOUT adding epoch
		// This avoids false positives where binary package epochs differ from source package epochs
		upstreamVersion := version.New(upstreamPkg.Version, pkg.VersionFormat(upstreamPkg))

		upstreamResults, err := provider.FindResults(
			search.ByPackageName(upstreamPkg.Name),
			search.ByDistro(rhelCompatibleDistro),
			internal.OnlyQualifiedPackages(upstreamPkg),
			internal.OnlyVulnerableVersions(upstreamVersion),
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

	// Filter out vulnerabilities where package version satisfies the unaffected constraint
	// (i.e., package IS safe according to AlmaLinux)
	filtered := disclosures.Remove(
		unaffectedResults.Filter(search.ByVersion(*pkgVersion)),
	)

	// Update remaining vulnerabilities with AlmaLinux fix information
	return filtered.UpdateByIdentity(unaffectedResults, replaceWithAlmaLinuxFixInfo)
}

// replaceWithAlmaLinuxFixInfo updates the Fix and Advisories fields from AlmaLinux unaffected data
// while preserving the match Details from the RHEL disclosure. This is used to replace RHEL fix
// versions with AlmaLinux-specific fix versions when available.
func replaceWithAlmaLinuxFixInfo(existing *result.Result, incoming result.Result) {
	// For each vulnerability in the existing result (RHEL disclosure)
	for i := range existing.Vulnerabilities {
		// Find the corresponding AlmaLinux vulnerability and extract fix info
		for _, incomingVuln := range incoming.Vulnerabilities {
			// Extract fix version from the unaffected constraint (e.g., ">= 2.4.48" -> "2.4.48")
			fixVersion := extractFixVersionFromConstraint(incomingVuln.Constraint)
			if fixVersion == "" {
				continue
			}

			// Update fix version and advisories to AlmaLinux's data
			existing.Vulnerabilities[i].Fix = vulnerability.Fix{
				Versions: []string{fixVersion},
				State:    vulnerability.FixStateFixed,
			}

			// Use advisories from database, or construct if missing
			advisories := incomingVuln.Advisories
			if len(advisories) == 0 {
				advisories = constructAdvisory(incomingVuln, existing.Package)
			}
			existing.Vulnerabilities[i].Advisories = advisories

			// Note: We keep existing.Details intact - those contain the RHEL match details
			break // Only need first match
		}
	}
}

// constructAdvisory builds advisory information from an ALSA vulnerability
// This is a fallback for databases that don't yet have advisory IDs in fix references.
// Once grype-db is updated to include advisory IDs, this will no longer be needed.
func constructAdvisory(vuln vulnerability.Vulnerability, pkg *pkg.Package) []vulnerability.Advisory {
	// Only construct for ALSA advisories
	if !strings.HasPrefix(vuln.ID, "ALSA-") {
		return nil
	}

	// Extract major version from package distro
	if pkg == nil || pkg.Distro == nil {
		return nil
	}

	majorVersion := pkg.Distro.Version
	if idx := strings.Index(majorVersion, "."); idx != -1 {
		majorVersion = majorVersion[:idx]
	}

	if majorVersion == "" {
		return nil
	}

	// Format: ALSA-YYYY:NNNN -> https://errata.almalinux.org/{major}/ALSA-YYYY-NNNN.html
	alsaURLID := strings.Replace(vuln.ID, ":", "-", 1) // ALSA-2025:2686 -> ALSA-2025-2686
	return []vulnerability.Advisory{
		{
			ID:   vuln.ID,
			Link: fmt.Sprintf("https://errata.almalinux.org/%s/%s.html", majorVersion, alsaURLID),
		},
	}
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
