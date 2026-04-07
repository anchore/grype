package rpm

import (
	"fmt"
	"regexp"
	"strconv"
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

// elVersionPattern matches patterns like "el9_5", "el8_10", "el7" in RPM release strings
var elVersionPattern = regexp.MustCompile(`\.el(\d+)(?:_(\d+))?`)

// extractRHELVersionFromRelease parses RHEL major/minor from release string.
// Examples:
//
//	"503.11.1.el9_5" -> (9, 5, true)
//	"82.el8_10.2" -> (8, 10, true)
//	"1.el7" -> (7, 0, true)  // missing minor treated as 0
//	"1.0.0" -> (0, 0, false)
func extractRHELVersionFromRelease(release string) (major, minor int, found bool) {
	matches := elVersionPattern.FindStringSubmatch(release)
	if matches == nil {
		return 0, 0, false
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, 0, false
	}

	// If no minor version captured, treat as 0 (base version)
	if matches[2] == "" {
		return major, 0, true
	}

	minor, err = strconv.Atoi(matches[2])
	if err != nil {
		return major, 0, true
	}

	return major, minor, true
}

// extractReleaseFromRPMVersion extracts release portion from full RPM version.
// Examples:
//
//	"5.14.0-503.11.1.el9_5" -> "503.11.1.el9_5"
//	"0:5.14.0-503.11.1.el9_5" -> "503.11.1.el9_5" (handles epoch)
func extractReleaseFromRPMVersion(rpmVersion string) string {
	// Strip epoch if present (e.g., "0:5.14.0-..." -> "5.14.0-...")
	if idx := strings.Index(rpmVersion, ":"); idx != -1 {
		rpmVersion = rpmVersion[idx+1:]
	}

	// Extract release portion after the hyphen
	if idx := strings.LastIndex(rpmVersion, "-"); idx != -1 {
		return rpmVersion[idx+1:]
	}

	return rpmVersion
}

// isFixReachableForEUS returns true if fix version is reachable for EUS distro.
// A fix is reachable if:
//  1. The fix's RHEL version cannot be determined (fail-open)
//  2. The fix's major version matches AND minor version <= EUS minor version
func isFixReachableForEUS(fixVersion string, eusDistro *distro.Distro) bool {
	if eusDistro == nil {
		return true
	}

	// Parse EUS distro version (e.g., "9.4" -> major=9, minor=4)
	eusMajor, eusMinor := eusDistro.MajorVersion(), eusDistro.MinorVersion()

	if eusMajor == "" {
		// Cannot determine EUS version, fail-open
		return true
	}

	eusMajorInt, err := strconv.Atoi(eusMajor)
	if err != nil {
		return true
	}

	// Treat missing minor version as 0 (e.g., "9+eus" means "9.0+eus")
	eusMinorInt := 0
	if eusMinor != "" {
		eusMinorInt, _ = strconv.Atoi(eusMinor)
	}

	// Extract release from fix version and parse RHEL version from it
	release := extractReleaseFromRPMVersion(fixVersion)
	fixMajor, fixMinor, found := extractRHELVersionFromRelease(release)
	if !found {
		// Cannot determine fix's RHEL version, fail-open (assume reachable)
		return true
	}

	// Different major version is not reachable
	if fixMajor != eusMajorInt {
		return false
	}

	// Fix is reachable only if fix's minor version <= EUS minor version
	// (missing minor is treated as 0, so ".el9" is reachable by any EUS version)
	return fixMinor <= eusMinorInt
}

func shouldUseRedhatEUSMatching(d *distro.Distro) bool {
	if d == nil {
		return false
	}

	if d.Type != distro.RedHat {
		// considering EUS fixes on a non-RedHat distro is not valid
		return false
	}

	for _, channel := range d.Channels {
		if strings.ToLower(channel) == "eus" {
			// if the distro has an EUS channel, we should consider EUS fixes
			return true
		}
	}
	return false
}

// redhatEUSMatches returns matches for the given package with Extended Update Support (EUS) fixes considered.
//
// RedHat follows the below workflow when incorporating patches:
//
//	RHEL 9 ───▶ 9.1 ───▶ 9.2 ───▶ 9.2-EUS (mainline + 9.2 EUS fixes)
//	                     │
//	                     ▼
//	                     9.3 ───▶ 9.4 ───▶ 9.4-EUS (mainline + 9.4 EUS fixes)
//	                              │
//	                              ▼
//	                              9.5 ───▶ 9.6 ───▶ 9.6-EUS (mainline + 9.6 EUS fixes)
//	                                       │
//	                                       ▼ ...
//
// So...
// - EUS branches are independent (no cross-EUS fixes)
// - each EUS branch = mainline fixes up to branch point + its own EUS fixes
//
// In grype that means that searching for vulnerabilities should be done in two steps:
// 1. find disclosures that match the base distro (e.g., '>= 9.0 && < 10').
// 2. find fixes from the base distro (e.g., '>= 9.0 && < 10') as well as EUS fixes for the specific minor version of the distro (e.g. '9.4+eus').
//
// Once searching is complete, we have two collections (matching for each search step above).
// We then merge these two (disclosure and resolution) collections together, the final result is a collection of
// prototype matches that the package is vulnerable to that include both the base distro disclosures and the EUS fixes.
// Any disclosure that does not apply to the original package version (e.g. a fix was found) at this point has been removed.
//
// The final step is to render the final matches from the merged collection.
func redhatEUSMatches(provider result.Provider, searchPkg pkg.Package, missingEpochStrategy version.MissingEpochStrategy) ([]match.Match, error) {
	distroWithoutEUS := *searchPkg.Distro
	distroWithoutEUS.Channels = nil // clear the EUS channel so that we can search for the base distro

	// Create version with config embedded
	pkgVersion := version.NewWithConfig(
		searchPkg.Version,
		pkg.VersionFormat(searchPkg),
		version.ComparisonConfig{
			MissingEpochStrategy: missingEpochStrategy,
		},
	)

	// find all disclosures for the package in the base distro (e.g. '>= 9.0 && < 10')
	disclosures, err := provider.FindResults(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(distroWithoutEUS), // e.g.  >= 9.0 && < 10 (no EUS channel)
		internal.OnlyQualifiedPackages(searchPkg),
		internal.OnlyVulnerableVersions(pkgVersion), // if these records indicate the version of the package is not vulnerable, do not include them
	)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch disclosures for distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	if len(disclosures) == 0 {
		return nil, nil
	}

	// find all base distro fixes (e.g. '>= 9.0 && < 10') and EUS fixes for the package in the specific minor version of the distro (e.g. '9.4+eus')
	resolutions, err := provider.FindResults(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(distroWithoutEUS, *searchPkg.Distro), // e.g.  (>= 9.0 && < 10) || 9.4+eus
		internal.OnlyQualifiedPackages(searchPkg),
		// note: we do **not** apply any version criteria to the search as to raise up all possible fixes
		// and combine within the collection. If we do filter on a fix version, it could result in
		// false positives (missing EUS fixes that resolve a disclosure).
	)

	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch resolutions for distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	eusFixes := resolutions.Filter(search.ByFixedVersion(*pkgVersion))

	// remove EUS fixed vulns for this version
	remaining := disclosures.Remove(eusFixes)

	// combine disclosures and fixes so that:
	// a. disclosures that have EUS fixes that resolve the disclosure for an earlier version of the package (thus we're not vulnerable) are removed.
	// b. disclosures that have EUS fixes that resolve the disclosure for future versions of the package (thus we're vulnerable) are kept.
	// c. all fixes from the incoming resolutions are patched onto the disclosures in the returned collection, so the
	//    final set of vulnerabilities is a fused set of disclosures and fixes together.
	// Note: we pass searchPkg.Distro (the EUS distro) to filter out fixes not reachable for this EUS version
	remaining = remaining.Merge(resolutions, mergeEUSAdvisoriesIntoMainDisclosures(pkgVersion, searchPkg.Distro))

	return remaining.ToMatches(), err
}

// mergeEUSAdvisoriesIntoMainDisclosures returns a function that will filter disclosures based on the provided advisory information (by fix version only).
// Additionally, this will merge applicable fixes into one vulnerability record, so that the final result contains only one vulnerability record per disclosure.
func mergeEUSAdvisoriesIntoMainDisclosures(v *version.Version, eusDistro *distro.Distro) func(disclosures, advisoryOverlays []result.Result) []result.Result {
	return func(disclosures, advisoryOverlays []result.Result) []result.Result {
		var out []result.Result

		for _, ds := range disclosures {
			processedResult := mergeEUSAdvisoryIntoMainDisclosure(v, ds, advisoryOverlays, eusDistro)
			if len(processedResult.Vulnerabilities) > 0 {
				out = append(out, processedResult)
			}
		}

		return out
	}
}

// mergeEUSAdvisoryIntoMainDisclosure processes a single disclosure Result against its corresponding advisory overlay Results
func mergeEUSAdvisoryIntoMainDisclosure(v *version.Version, disclosures result.Result, advisoryOverlays []result.Result, eusDistro *distro.Distro) result.Result {
	processedResult := result.Result{
		ID:      disclosures.ID,
		Package: disclosures.Package,
	}

	// process each disclosure vulnerability against advisory overlays
	for _, disclosure := range disclosures.Vulnerabilities {
		processedVuln, advisoryDetails := mergeEUSAdvisoryIntoSingleDisclosure(v, disclosure, advisoryOverlays, eusDistro)
		if processedVuln != nil {
			processedResult.Vulnerabilities = append(processedResult.Vulnerabilities, *processedVuln)
			processedResult.Details = append(processedResult.Details, advisoryDetails...)
		}
	}

	finalizeMatchDetails(&processedResult, disclosures.Details, v)
	return processedResult
}

// mergeEUSAdvisoryIntoSingleDisclosure processes a single vulnerability against advisory overlays
func mergeEUSAdvisoryIntoSingleDisclosure(v *version.Version, disclosure vulnerability.Vulnerability, advisoryOverlays []result.Result, eusDistro *distro.Distro) (*vulnerability.Vulnerability, match.Details) {
	fixVersions := version.NewSet(true)
	var constraints []version.Constraint
	var state vulnerability.FixState
	var allAdvisoryDetails match.Details

	// check if we're vulnerable to the original disclosure
	if isVulnerableVersion(v, disclosure.Constraint, disclosure.ID) {
		constraints = append(constraints, disclosure.Constraint)
	}

	// process advisory overlays, incorporating new fix versions and updating the version constraints
	for _, advisoryOverlay := range advisoryOverlays {
		collectMatchingConstraintsDetailsAndFixState(v, advisoryOverlay, fixVersions, &constraints, &state, &allAdvisoryDetails, eusDistro)
	}

	if len(constraints) == 0 {
		// all of the advisories showed we're not vulnerable, so we can skip this disclosure
		return nil, nil
	}

	patchedRecord := buildPatchedVulnerabilityRecord(v, disclosure, fixVersions, constraints, state)
	return &patchedRecord, allAdvisoryDetails
}

// collectMatchingConstraintsDetailsAndFixState processes vulnerabilities from advisory overlays, applying any new fix versions and updating the given fix state / constraints.
func collectMatchingConstraintsDetailsAndFixState(v *version.Version, advisoryResult result.Result, fixVersions *version.Set, constraints *[]version.Constraint, state *vulnerability.FixState, allAdvisoryDetails *match.Details, eusDistro *distro.Distro) {
	advisories := advisoryResult.Vulnerabilities
	var keepDetails bool
	for _, advisory := range advisories {
		if advisory.Fix.State == vulnerability.FixStateWontFix && *state != vulnerability.FixStateFixed {
			*state = advisory.Fix.State
		}

		// Get all fixes greater than current version (parses versions once)
		allFixes := neededFixes(v, advisory.Fix.Versions, advisory.Constraint.Format(), advisory.ID)

		// Filter to only those reachable for EUS (quick string-based check)
		applicableFixes := filterFixesForEUS(allFixes, eusDistro, advisory.ID)

		if len(applicableFixes) == 0 {
			// If there were fixes but none are reachable for EUS, mark as NotFixed
			if len(allFixes) > 0 && eusDistro != nil && *state != vulnerability.FixStateFixed {
				*state = vulnerability.FixStateNotFixed
				// Still add the constraint since the user is vulnerable
				*constraints = append(*constraints, advisory.Constraint)
				keepDetails = true
			}
			// none of the fixes on this advisory are greater than the current version (or reachable for EUS), so we can skip adding fixes
			continue
		}

		// we're vulnerable! keep any fix versions that could have been applied
		*constraints = append(*constraints, advisory.Constraint)
		fixVersions.Add(applicableFixes...)
		if *state != vulnerability.FixStateFixed {
			*state = advisory.Fix.State
		}
		keepDetails = true
	}

	// collect details from the advisory overlay only if we kept any of the advisory details
	if keepDetails && len(advisoryResult.Details) > 0 {
		*allAdvisoryDetails = append(*allAdvisoryDetails, advisoryResult.Details...)
	}
}

// buildPatchedVulnerabilityRecord creates the final patched vulnerability record from the original disclosure and fix/constraint information from applicable advisories.
func buildPatchedVulnerabilityRecord(v *version.Version, disclosure vulnerability.Vulnerability, fixVersions *version.Set, constraints []version.Constraint, state vulnerability.FixState) vulnerability.Vulnerability {
	patchedRecord := disclosure

	if state == vulnerability.FixStateFixed {
		patchedRecord.Fix.Versions = nil
		for _, fixVersion := range fixVersions.Values() {
			patchedRecord.Fix.Versions = append(patchedRecord.Fix.Versions, fixVersion.Raw)
			fixConstraint, err := version.GetConstraint(fmt.Sprintf("< %s", fixVersion.Raw), v.Format)
			if err != nil {
				log.WithFields("vulnerability", disclosure.ID, "fixVersion", fixVersion, "error", err).Trace("failed to create constraint for fix version")
				continue // skip this fix version if we cannot create a constraint
			}
			constraints = append(constraints, fixConstraint)
		}
	}

	patchedRecord.Fix.State = finalizeFixState(disclosure, state)
	patchedRecord.Constraint = version.CombineConstraints(constraints...)
	return patchedRecord
}

// finalizeMatchDetails patches the processed result details with that of details in the post-processed result.
func finalizeMatchDetails(processedResult *result.Result, originalDetails match.Details, v *version.Version) {
	if len(processedResult.Vulnerabilities) == 0 {
		return
	}

	// keep details around only if we have vulnerabilities they describe
	processedResult.Details = append(processedResult.Details, originalDetails...)
	processedResult.Details = result.NewMatchDetailsSet(processedResult.Details...).ToSlice()

	// patch the version in the details if it is missing
	for idx := range processedResult.Details {
		d := &processedResult.Details[idx]

		switch params := d.SearchedBy.(type) {
		case match.CPEParameters:
			if params.Package.Version == "" {
				params.Package.Version = v.Raw
				d.SearchedBy = params
			}
		case match.DistroParameters:
			if params.Package.Version == "" {
				params.Package.Version = v.Raw
				d.SearchedBy = params
			}
		case match.EcosystemParameters:
			if params.Package.Version == "" {
				params.Package.Version = v.Raw
				d.SearchedBy = params
			}
		}
	}
}

func isVulnerableVersion(v *version.Version, c version.Constraint, id string) bool {
	if c == nil {
		// nil constraint is different than an empty constraint, so we should not consider this vulnerable
		return false
	}

	isVulnerable, err := c.Satisfied(v)
	if err != nil {
		log.WithFields("vulnerability", id, "error", err).Trace("failed to check constraint")
		return false // if we cannot determine if the version is vulnerable, we assume it is not
	}

	return isVulnerable
}

func neededFixes(v *version.Version, fixVersions []string, format version.Format, id string) []*version.Version {
	var needed []*version.Version
	for _, fixVersion := range fixVersions {
		fixVersionObj := version.New(fixVersion, format) // note: we use the format from the advisory, not the version itself
		res, err := v.Is(version.LT, fixVersionObj)
		if err != nil {
			log.WithFields("format", format, "version", fixVersion, "error", err, "vulnerability", id).Trace("failed to evaluate fix version")
			continue
		}
		if res {
			needed = append(needed, fixVersionObj)
		}
	}

	return needed
}

// filterFixesForEUS filters a list of fix versions to only those reachable for the given EUS distro.
func filterFixesForEUS(fixes []*version.Version, eusDistro *distro.Distro, id string) []*version.Version {
	if eusDistro == nil {
		return fixes
	}

	var reachable []*version.Version
	for _, fix := range fixes {
		if isFixReachableForEUS(fix.Raw, eusDistro) {
			reachable = append(reachable, fix)
		} else {
			log.WithFields("vulnerability", id, "fixVersion", fix.Raw, "eusDistro", eusDistro.String()).Trace("skipping fix not reachable for EUS version")
		}
	}
	return reachable
}

func finalizeFixState(record vulnerability.Vulnerability, state vulnerability.FixState) vulnerability.FixState {
	if state == "" {
		state = vulnerability.FixStateUnknown
	}

	if state != vulnerability.FixStateUnknown {
		return state
	}

	if record.Fix.State != vulnerability.FixStateUnknown {
		return record.Fix.State
	}

	return vulnerability.FixStateUnknown
}
