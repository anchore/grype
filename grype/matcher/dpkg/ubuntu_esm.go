package dpkg

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

// IgnoreReasonDistroNotVulnerable - the distro vendor explicitly says the package is unaffected. For Ubuntu ESM
// this is emitted when an esm-overlay "fixed" row resolves a base disclosure as no-longer-vulnerable.
const IgnoreReasonDistroNotVulnerable = "Distro Not Vulnerable"

func shouldUseUbuntuESMMatching(d *distro.Distro) bool {
	if d == nil {
		return false
	}

	if d.Type != distro.Ubuntu {
		// considering ESM fixes on a non-Ubuntu distro is not valid
		return false
	}

	for _, channel := range d.Channels {
		if strings.ToLower(channel) == "esm" {
			// if the distro has an ESM channel, we should consider ESM fixes
			return true
		}
	}
	return false
}

// ubuntuESMMatches returns matches for the given package with Extended Security Maintenance (ESM / Ubuntu Pro) fixes
// considered. It mirrors the RHEL EUS disclosure/resolution split (see redhatEUSMatches):
//
// Ubuntu freezes a release's package versions at the end of standard support; ESM (esm-infra + esm-apps) then
// continues to publish fixes on the same version line as a "+esm" build. So searching is done in two steps:
//  1. find disclosures that match the base distro (e.g. 'ubuntu:16.04'), which carry the base won't-fix rows.
//  2. find fixes from both the base distro AND the ESM channel (e.g. 'ubuntu:16.04' || 'ubuntu:16.04+esm').
//
// The two collections (disclosure and resolution) are merged: any disclosure that the resolution fixes for the
// installed version is dropped, the rest are kept with the ESM fix version patched on.
//
// Unlike RHEL EUS there is no cross-minor reachability problem: Ubuntu ESM is one line per LTS release and the
// resolution search only pulls same-minor 'ubuntu:XX.YY' and 'ubuntu:XX.YY+esm' rows, so every '+esm' fix pulled
// is reachable by construction.
func ubuntuESMMatches(provider result.Provider, searchPkg pkg.Package, missingEpochStrategy version.MissingEpochStrategy, extra ...vulnerability.Criteria) ([]match.Match, []match.IgnoreFilter, error) {
	distroWithoutESM := *searchPkg.Distro
	distroWithoutESM.Channels = nil // clear the ESM channel so that we can search for the base distro

	pkgVersion := version.NewWithConfig(
		searchPkg.Version,
		pkg.VersionFormat(searchPkg),
		version.ComparisonConfig{
			MissingEpochStrategy: missingEpochStrategy,
		},
	)

	disclosureCriteria := []vulnerability.Criteria{
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(distroWithoutESM), // e.g. ubuntu:16.04 (no ESM channel)
		internal.OnlyQualifiedPackages(searchPkg),
		internal.OnlyVulnerableVersions(pkgVersion),
	}
	disclosureCriteria = append(disclosureCriteria, extra...)

	// find all disclosures for the package in the base distro (e.g. ubuntu:16.04)
	disclosures, err := provider.FindResults(disclosureCriteria...)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch disclosures for distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	if len(disclosures) == 0 {
		return nil, nil, nil
	}

	resolutionCriteria := []vulnerability.Criteria{
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(distroWithoutESM, *searchPkg.Distro), // e.g. ubuntu:16.04 || ubuntu:16.04+esm
		internal.OnlyQualifiedPackages(searchPkg),
		// note: we do **not** apply any version criteria to the search as to raise up all possible fixes
		// and combine within the collection. If we do filter on a fix version, it could result in
		// false positives (missing ESM fixes that resolve a disclosure).
	}
	resolutionCriteria = append(resolutionCriteria, extra...)

	// find all base distro fixes and ESM fixes for the package (e.g. ubuntu:16.04 || ubuntu:16.04+esm)
	resolutions, err := provider.FindResults(resolutionCriteria...)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch resolutions for distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	esmFixes := resolutions.Filter(search.ByFixedVersion(*pkgVersion))

	// remove ESM fixed vulns for this version
	remaining := disclosures.Remove(esmFixes)

	// combine disclosures and fixes so that:
	// a. disclosures that have ESM fixes that resolve the disclosure for an earlier version of the package (thus we're not vulnerable) are removed.
	// b. disclosures that have ESM fixes that resolve the disclosure for future versions of the package (thus we're vulnerable) are kept.
	// c. all fixes from the incoming resolutions are patched onto the disclosures in the returned collection, so the
	//    final set of vulnerabilities is a fused set of disclosures and fixes together.
	remaining = remaining.Merge(resolutions, mergeESMAdvisoriesIntoMainDisclosures(pkgVersion))

	return remaining.ToMatches(), internal.OwnershipIgnores(searchPkg, IgnoreReasonDistroNotVulnerable, esmFixes.Vulnerabilities()...), nil
}

// mergeESMAdvisoriesIntoMainDisclosures returns a function that filters disclosures based on the provided advisory
// information (by fix version only) and merges applicable fixes into one vulnerability record, so the final result
// contains only one vulnerability record per disclosure.
func mergeESMAdvisoriesIntoMainDisclosures(v *version.Version) func(disclosures, advisoryOverlays []result.Result) []result.Result {
	return func(disclosures, advisoryOverlays []result.Result) []result.Result {
		var out []result.Result

		for _, ds := range disclosures {
			processedResult := mergeESMAdvisoryIntoMainDisclosure(v, ds, advisoryOverlays)
			if len(processedResult.Vulnerabilities) > 0 {
				out = append(out, processedResult)
			}
		}

		return out
	}
}

// mergeESMAdvisoryIntoMainDisclosure processes a single disclosure Result against its corresponding advisory overlay Results.
func mergeESMAdvisoryIntoMainDisclosure(v *version.Version, disclosures result.Result, advisoryOverlays []result.Result) result.Result {
	processedResult := result.Result{
		ID:      disclosures.ID,
		Package: disclosures.Package,
	}

	for _, disclosure := range disclosures.Vulnerabilities {
		processedVuln, advisoryDetails := mergeESMAdvisoryIntoSingleDisclosure(v, disclosure, advisoryOverlays)
		if processedVuln != nil {
			processedResult.Vulnerabilities = append(processedResult.Vulnerabilities, *processedVuln)
			processedResult.Details = append(processedResult.Details, advisoryDetails...)
		}
	}

	finalizeMatchDetails(&processedResult, disclosures.Details, v)
	return processedResult
}

// mergeESMAdvisoryIntoSingleDisclosure processes a single vulnerability against advisory overlays.
func mergeESMAdvisoryIntoSingleDisclosure(v *version.Version, disclosure vulnerability.Vulnerability, advisoryOverlays []result.Result) (*vulnerability.Vulnerability, match.Details) {
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
		collectMatchingConstraintsDetailsAndFixState(v, advisoryOverlay, fixVersions, &constraints, &state, &allAdvisoryDetails)
	}

	if len(constraints) == 0 {
		// all of the advisories showed we're not vulnerable, so we can skip this disclosure
		return nil, nil
	}

	patchedRecord := buildPatchedVulnerabilityRecord(v, disclosure, fixVersions, constraints, state)
	return &patchedRecord, allAdvisoryDetails
}

// collectMatchingConstraintsDetailsAndFixState processes vulnerabilities from advisory overlays, applying any new fix
// versions and updating the given fix state / constraints.
func collectMatchingConstraintsDetailsAndFixState(v *version.Version, advisoryResult result.Result, fixVersions *version.Set, constraints *[]version.Constraint, state *vulnerability.FixState, allAdvisoryDetails *match.Details) {
	advisories := advisoryResult.Vulnerabilities
	var keepDetails bool
	for _, advisory := range advisories {
		if advisory.Fix.State == vulnerability.FixStateWontFix && *state != vulnerability.FixStateFixed {
			*state = advisory.Fix.State
		}

		// get all fixes greater than current version (parses versions once). unlike RHEL EUS (see filterFixesForEUS)
		// there is no reachability filter: Ubuntu ESM is one line per LTS release and the resolution search only pulls
		// same-minor 'ubuntu:XX.YY' and 'ubuntu:XX.YY+esm' rows, so every '+esm' fix is reachable by construction.
		applicableFixes := neededFixes(v, advisory.Fix.Versions, advisory.Constraint.Format(), advisory.ID)

		if len(applicableFixes) == 0 {
			// none of the fixes on this advisory are greater than the current version, so we can skip adding fixes
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

// buildPatchedVulnerabilityRecord creates the final patched vulnerability record from the original disclosure and
// fix/constraint information from applicable advisories.
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
