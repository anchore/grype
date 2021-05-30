package common

import (
	"fmt"
	"sort"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/scylladb/go-set/strset"
)

type CPESearchInput struct {
	Namespace string   `json:"namespace"`
	CPEs      []string `json:"cpes"`
}

func (i *CPESearchInput) Merge(other CPESearchInput) error {
	if i.Namespace != other.Namespace {
		return fmt.Errorf("namespaces do not match")
	}

	existingCPEs := strset.New(i.CPEs...)
	newCPEs := strset.New(other.CPEs...)
	mergedCPEs := strset.Union(existingCPEs, newCPEs).List()
	sort.Strings(mergedCPEs)
	i.CPEs = mergedCPEs
	return nil
}

type CPESearchHit struct {
	VersionConstraint string   `json:"versionConstraint"`
	CPEs              []string `json:"cpes"`
}

func (h CPESearchHit) Equals(other CPESearchHit) bool {
	if h.VersionConstraint != other.VersionConstraint {
		return false
	}

	if len(h.CPEs) != len(other.CPEs) {
		return false
	}

	for i := range h.CPEs {
		if h.CPEs[i] != other.CPEs[i] {
			return false
		}
	}

	return true
}

// FindMatchesByPackageCPE retrieves all vulnerabilities that match the generated CPE
func FindMatchesByPackageCPE(store vulnerability.ProviderByCPE, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	matchesByFingerprint := make(map[match.Fingerprint]match.Match)
	for _, cpe := range p.CPEs {
		// prefer the CPE version, but if npt specified use the package version
		pkgVersion := cpe.Version
		if pkgVersion == wfn.NA || pkgVersion == wfn.Any {
			pkgVersion = p.Version
		}
		verObj, err := version.NewVersion(pkgVersion, version.FormatFromPkgType(p.Type))
		if err != nil {
			return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
		}

		// find all vulnerability records in the DB for the given CPE (not including version comparisons)
		allPkgVulns, err := store.GetByCPE(cpe)
		if err != nil {
			return nil, fmt.Errorf("matcher failed to fetch by CPE pkg='%s': %w", p.Name, err)
		}

		// for each vulnerability record found, check the version constraint. If the constraint is satisfied
		// relative to the current version information from the CPE (or the package) then the given package
		// is vulnerable.
		for _, vuln := range allPkgVulns {
			isPackageVulnerable, err := vuln.Constraint.Satisfied(verObj)
			if err != nil {
				return nil, fmt.Errorf("cpe matcher failed to check constraint='%s' version='%s': %w", vuln.Constraint, verObj, err)
			}

			if !isPackageVulnerable {
				continue
			}

			addNewMatch(matchesByFingerprint, vuln, p, verObj, upstreamMatcher, cpe)
		}
	}

	return toMatches(matchesByFingerprint), nil
}

func addNewMatch(matchesByFingerprint map[match.Fingerprint]match.Match, vuln vulnerability.Vulnerability, p pkg.Package, pkgVersion *version.Version, upstreamMatcher match.MatcherType, searchedByCPE syftPkg.CPE) {
	candidateMatch := match.Match{
		Type:          match.FuzzyMatch,
		Vulnerability: vuln,
		Package:       p,
	}

	if existingMatch, exists := matchesByFingerprint[candidateMatch.Fingerprint()]; exists {
		candidateMatch = existingMatch
	}

	candidateMatch.MatchDetails = addMatchDetails(candidateMatch.MatchDetails,
		match.Details{
			Confidence: 0.9, // TODO: this is hard coded for now
			Matcher:    upstreamMatcher,
			SearchedBy: CPESearchInput{
				Namespace: vuln.Namespace,
				CPEs: []string{
					searchedByCPE.BindToFmtString(),
				},
			},
			MatchedOn: CPESearchHit{
				VersionConstraint: vuln.Constraint.String(),
				CPEs:              cpesToString(keepMatchingCPEs(pkgVersion, vuln.CPEs)),
			},
		},
	)

	matchesByFingerprint[candidateMatch.Fingerprint()] = candidateMatch
}

func addMatchDetails(existingDetails []match.Details, newDetails match.Details) []match.Details {
	newMatchedOn, ok := newDetails.MatchedOn.(CPESearchHit)
	if !ok {
		return existingDetails
	}

	newSearchedBy, ok := newDetails.SearchedBy.(CPESearchInput)
	if !ok {
		return existingDetails
	}
	for idx, detail := range existingDetails {
		matchedOn, ok := detail.MatchedOn.(CPESearchHit)
		if !ok {
			continue
		}

		searchedBy, ok := detail.SearchedBy.(CPESearchInput)
		if !ok {
			continue
		}

		if !matchedOn.Equals(newMatchedOn) {
			continue
		}

		err := searchedBy.Merge(newSearchedBy)
		if err != nil {
			continue
		}

		existingDetails[idx].SearchedBy = searchedBy
		return existingDetails
	}

	// could not merge with another entry, append to the end
	existingDetails = append(existingDetails, newDetails)
	return existingDetails
}

func keepMatchingCPEs(pkgVersion *version.Version, allCPEs []syftPkg.CPE) (matchedCPEs []syftPkg.CPE) {
	for _, c := range allCPEs {
		if c.Version == wfn.Any || c.Version == wfn.NA {
			matchedCPEs = append(matchedCPEs, c)
			continue
		}

		constraint, err := version.GetConstraint(c.Version, version.UnknownFormat)
		if err != nil {
			// if we can't get a version constraint, don't filter out the CPE
			matchedCPEs = append(matchedCPEs, c)
			continue
		}

		satisfied, err := constraint.Satisfied(pkgVersion)
		if err != nil || satisfied {
			// if we can't check for version satisfaction, don't filter out the CPE
			matchedCPEs = append(matchedCPEs, c)
			continue
		}
	}
	return matchedCPEs
}

func toMatches(matchesByFingerprint map[match.Fingerprint]match.Match) (matches []match.Match) {
	for _, m := range matchesByFingerprint {
		matches = append(matches, m)
	}
	sort.Sort(match.ByElements(matches))
	return matches
}

// cpesToString receives one or more CPEs and stringifies them
func cpesToString(cpes []syftPkg.CPE) []string {
	var strs = make([]string, len(cpes))
	for idx, cpe := range cpes {
		strs[idx] = cpe.BindToFmtString()
	}
	sort.Strings(strs)
	return strs
}
