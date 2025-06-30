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
	var matches []match.Match

	provider := result.NewProvider(vp, p, m.Type())

	// 1. let's match with the package given to us (direct match)....

	// Regarding RPM epochs... we know that the package and vulnerability will have
	// well-specified epochs since both are sourced from either the RPM DB directly or
	// the upstream RedHat vulnerability data. Note: this is very much UNLIKE our
	// matching on a source package above where the epoch could be dropped in the
	// reference data. This means that any missing epoch CAN be assumed to be zero,
	// as it falls into the case of "the project elected to NOT have an epoch for the
	// first version scheme" and not into any other case.

	// For this reason match exactly on a package, we should be EXPLICIT about the
	// epoch (since downstream version comparison logic will strip the epoch during
	// comparison for the above-mentioned reasons --essentially for the source RPM
	// case). To do this, we fill in missing epoch values in the package versions with
	// an explicit 0.

	exactMatches, err := m.matchPackage(provider, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by exact package name: %w", err)
	}

	matches = append(matches, exactMatches...)

	// 2. let's match with a synthetic package based on the sourceRPM...

	// Regarding RPM epoch and comparisons... RedHat is explicit that when an RPM
	// epoch is not specified that it should be assumed to be zero (see
	// https://github.com/rpm-software-management/rpm/issues/450). This comment from
	// RedHat is applicable for a project that has elected to not use epoch and has
	// not changed their version scheme at all --therefore it is safe to assume that
	// the epoch (though not specified) is 0. However, in cases where there may be a
	// non-zero epoch and it has been omitted from the version string, it is NOT safe
	// to assume an epoch of 0... as this could lead to misleading comparison
	// results.

	// For example, take the perl-Errno package:
	//		name: 		perl-Errno
	//		version:	0:1.28-419.el8_4.1
	//		sourceRPM:	perl-5.26.3-419.el8_4.1.src.rpm

	// Say we have a vulnerability with the following information (note this is
	// against the SOURCE package "perl", not the target package, "perl-Errno"):
	// 		ID:					CVE-2020-10543
	//		Package Name:		perl
	//		Version constraint:	< 4:5.26.3-419.el8

	// Note that the vulnerability information has complete knowledge about the
	// version and it's lineage (epoch + version), however, the source package
	// information for perl-Errno does not include any information about epoch. With
	// the rule from RedHat we should assume a 0 epoch and make the comparison:

	//		0:5.26.3-419.el8 < 4:5.26.3-419.el8 = true! ... therefore, we've been vulnerable since epoch 0 < 4.
	//                                                  ... this is an INVALID comparison!

	// The problem with this is that sourceRPMs tend to not specify epoch even though
	// there may be a non-zero epoch for that package! This is important. The "more
	// correct" thing to do in this case is to drop the epoch:

	//		5.26.3-419.el8 < 5.26.3-419.el8 = false!    ... these are the SAME VERSION

	// There is still a problem with this approach: it essentially makes an
	// assumption that a missing epoch really is the SAME epoch to the other version
	// being compared (in our example, no perl epoch on one side means we should
	// really assume an epoch of 4 on the other side). This could still lead to
	// problems since an epoch delimits potentially non-comparable version lineages.

	sourceMatches, err := m.matchUpstreamPackages(provider, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to match by source indirection: %w", err)
	}
	matches = append(matches, sourceMatches...)

	return matches, nil, nil
}

func (m *Matcher) matchPackage(provider result.Provider, p pkg.Package) ([]match.Match, error) {
	// we want to ensure that the version ALWAYS has an epoch specified...
	originalPkg := p

	addEpochIfApplicable(&p)

	matches, err := m.findMatches(provider, p)
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities by dpkg source indirection: %w", err)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the modified package).
	// At the same time, we still want this to be treated as a direct match, thus using a reference package in the search
	// is not correct.
	for idx := range matches {
		matches[idx].Package = originalPkg
	}

	return matches, nil
}

func (m *Matcher) matchUpstreamPackages(provider result.Provider, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indirectMatches, err := m.findMatches(provider, indirectPackage)
		if err != nil {
			return nil, fmt.Errorf("failed to find vulnerabilities for rpm upstream source package: %w", err)
		}
		matches = append(matches, indirectMatches...)
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

	if isEUSContext(searchPkg.Distro) {
		return m.findEUSMatches(provider, searchPkg)
	}

	// Non-EUS matching...

	disclosures, err := provider.FindResults(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		internal.OnlyQualifiedPackages(searchPkg),
		internal.OnlyVulnerableVersions(version.NewVersionFromPkg(searchPkg)),
	)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch disclosures for distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	return disclosures.ToMatches(), nil
}

func (m *Matcher) findEUSMatches(provider result.Provider, searchPkg pkg.Package) ([]match.Match, error) {
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

func isEUSContext(d *distro.Distro) bool {
	if d == nil {
		return false
	}

	return strings.ToLower(d.Channel) == "eus"
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
