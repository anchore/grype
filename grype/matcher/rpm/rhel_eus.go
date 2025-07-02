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

func shouldUseRedhatEUS(d *distro.Distro, pref EUSPreference) bool {
	if d == nil || pref == EUSPreferenceNever {
		return false
	}

	if d.Type != distro.RedHat {
		// considering EUS fixes on a non-RedHat distro is not valid
		return false
	}

	return pref == EUSPreferenceAlways || strings.ToLower(d.Channel) == "eus"
}

func findRedhatEUSMatches(provider result.Provider, searchPkg pkg.Package) ([]match.Match, error) {
	distroWithoutEUS := *searchPkg.Distro
	distroWithoutEUS.Channel = "" // clear the EUS designator so that we can search for the base distro

	disclosures, err := provider.FindResults(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(distroWithoutEUS), // e.g.  >= 9.0 && < 10
		internal.OnlyQualifiedPackages(searchPkg),
	)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch disclosures for distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	if len(disclosures) == 0 {
		return nil, nil
	}

	resolutions, err := provider.FindResults(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(distroWithoutEUS, *searchPkg.Distro), // e.g.  (>= 9.0 && < 10) || 9.4+eus
		internal.OnlyQualifiedPackages(searchPkg),
		// note: we do not apply any version criteria to the search as to raise up all possible fixes and combine within
		// the collection.
		// If we do filter on a fix version, it will result in false positives (missing EUS fixes).
	)

	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch resolutions for distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	remaining := disclosures.Merge(resolutions, resolveDisclosures(version.NewVersionFromPkg(searchPkg), false))

	return remaining.ToMatches(), err
}

// resolveDisclosures returns a function that will filter disclosures based on the provided advisory information (by fix version only).
// Additionally, this will merge applicable fixes into one vulnerability record, so that the final result contains only one vulnerability record per disclosure.
func resolveDisclosures(v *version.Version, treatResolutionsAsDisclosures bool) func(disclosures, advisoryOverlays []result.Result) []result.Result {
	return func(disclosures, advisoryOverlays []result.Result) []result.Result {
		var out []result.Result

		for _, ds := range disclosures {
			// find the corresponding advisory overlay results for this ID
			var as []result.Result
			for _, advisory := range advisoryOverlays {
				if advisory.ID == ds.ID {
					as = append(as, advisory)
				}
			}

			processedResult := processDisclosureResult(v, ds, as)
			if len(processedResult.Vulnerabilities) > 0 {
				out = append(out, processedResult)
			}
		}

		if treatResolutionsAsDisclosures {
			// add any incoming results that don't have corresponding existing results
			for _, advisory := range advisoryOverlays {
				hasCorrespondingExisting := false
				for _, e := range disclosures {
					if e.ID == advisory.ID {
						hasCorrespondingExisting = true
						break
					}
				}
				if !hasCorrespondingExisting {
					// this advisory doesn't have a corresponding disclosure, include it as-is
					// note: we are presuming that the original disclosure has already been verified to be vulnerable
					// against the original package.
					out = append(out, advisory)
				}
			}
		}

		return out
	}
}

// processDisclosureResult processes a single disclosure Result against its corresponding advisory overlay Results
func processDisclosureResult(v *version.Version, disclosures result.Result, advisoryOverlays []result.Result) result.Result {
	processedResult := result.Result{
		ID:      disclosures.ID,
		Package: disclosures.Package,
	}

	// process each disclosure vulnerability against advisory overlays
	for _, disclosure := range disclosures.Vulnerabilities {
		processedVuln, advisoryDetails := processVulnerabilityWithAdvisories(v, disclosure, advisoryOverlays)
		if processedVuln != nil {
			processedResult.Vulnerabilities = append(processedResult.Vulnerabilities, *processedVuln)
			processedResult.Details = append(processedResult.Details, advisoryDetails...)
		}
	}

	finalizeProcessedResult(&processedResult, disclosures.Details, v)
	return processedResult
}

// processVulnerabilityWithAdvisories processes a single vulnerability against advisory overlays
func processVulnerabilityWithAdvisories(v *version.Version, disclosure vulnerability.Vulnerability, advisoryOverlays []result.Result) (*vulnerability.Vulnerability, match.Details) {
	fixVersions := version.Set{}
	var constraints []version.Constraint
	var state vulnerability.FixState
	var allAdvisoryDetails match.Details

	// check if we're vulnerable to the original disclosure
	if isVulnerableVersion(v, disclosure.Constraint, disclosure.ID) {
		constraints = append(constraints, disclosure.Constraint)
	}

	// process advisory overlays
	for _, advisoryOverlay := range advisoryOverlays {
		allAdvisoryDetails = append(allAdvisoryDetails, advisoryOverlay.Details...)
		processAdvisoryVulnerabilities(v, advisoryOverlay.Vulnerabilities, &fixVersions, &constraints, &state)
	}

	if len(constraints) == 0 {
		// all of the advisories showed we're not vulnerable, so we can skip this disclosure
		return nil, nil
	}

	patchedRecord := buildPatchedVulnerabilityRecord(v, disclosure, fixVersions, constraints, state)
	return &patchedRecord, allAdvisoryDetails
}

// processAdvisoryVulnerabilities processes vulnerabilities from advisory overlays
func processAdvisoryVulnerabilities(v *version.Version, advisories []vulnerability.Vulnerability, fixVersions *version.Set, constraints *[]version.Constraint, state *vulnerability.FixState) {
	for _, advisory := range advisories {
		if advisory.Fix.State == vulnerability.FixStateWontFix && *state != vulnerability.FixStateFixed {
			*state = advisory.Fix.State
		}

		applicableFixes := neededFixes(v, advisory.Fix.Versions, advisory.Constraint.Format(), advisory.ID)
		if len(applicableFixes) == 0 {
			// none of the fixes on this advisory are greater than the current version, so we can skip this advisory
			continue
		}

		// we're vulnerable! keep any fix versions that could have been applied
		*constraints = append(*constraints, advisory.Constraint)
		fixVersions.Add(applicableFixes...)
		if *state != vulnerability.FixStateFixed {
			*state = advisory.Fix.State
		}
	}
}

// buildPatchedVulnerabilityRecord creates the final patched vulnerability record
func buildPatchedVulnerabilityRecord(v *version.Version, disclosure vulnerability.Vulnerability, fixVersions version.Set, constraints []version.Constraint, state vulnerability.FixState) vulnerability.Vulnerability {
	patchedRecord := disclosure

	if state == vulnerability.FixStateFixed {
		patchedRecord.Fix.Versions = nil
		for _, fixVersion := range fixVersions.Values() {
			patchedRecord.Fix.Versions = append(patchedRecord.Fix.Versions, fixVersion.Raw)
			fixConstraint, err := version.GetConstraint(fmt.Sprintf("< %s", fixVersion), v.Format)
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

// finalizeProcessedResult finalizes the processed result by adding details and patching version info
func finalizeProcessedResult(processedResult *result.Result, originalDetails match.Details, v *version.Version) {
	if len(processedResult.Vulnerabilities) == 0 {
		return
	}

	// keep details around only if we have vulnerabilities they describe
	processedResult.Details = append(processedResult.Details, originalDetails...)
	processedResult.Details = internal.NewMatchDetailsSet(processedResult.Details...).ToSlice()

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
		fixVersionObj := version.NewVersion(fixVersion, format) // note: we use the format from the advisory, not the version itself
		res, err := v.Evaluate(version.LT, fixVersionObj)
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
