package apk

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/common"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/jinzhu/copier"
	"github.com/scylladb/go-set/strset"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.ApkPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.ApkMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	var matches = make([]match.Match, 0)

	// direct matches with package
	directMatches, err := m.findApkPackage(store, d, p)
	if err != nil {
		return nil, err
	}
	matches = append(matches, directMatches...)

	// indirect matches with package source
	indirectMatches, err := m.matchBySourceIndirection(store, d, p)
	if err != nil {
		return nil, err
	}
	matches = append(matches, indirectMatches...)

	return matches, nil
}

func (m *Matcher) cpeMatchesWithoutSecDBFixes(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	// find CPE-indexed vulnerability matches specific to the given package name and version
	cpeMatches, err := common.FindMatchesByPackageCPE(store, p, m.Type())
	if err != nil {
		return nil, err
	}

	cpeMatchesByID := matchesByID(cpeMatches)

	// remove cpe matches where there is an entry in the secDB for the particular package-vulnerability pairing, and the
	// installed package version is >= the fixed in version for the secDB record.
	secDBVulnerabilities, err := store.GetByDistro(d, p)
	if err != nil {
		return nil, err
	}

	secDBVulnerabilitiesByID := vulnerabilitiesByID(secDBVulnerabilities)

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	var finalCpeMatches []match.Match

cveLoop:
	for id, cpeMatchesForID := range cpeMatchesByID {
		// check to see if there is a secdb entry for this ID (CVE)
		secDBVulnerabilitiesForID, exists := secDBVulnerabilitiesByID[id]
		if !exists {
			// does not exist in secdb, so the CPE record(s) should be added to the final results
			finalCpeMatches = append(finalCpeMatches, cpeMatchesForID...)
			continue
		}

		// there is a secdb entry...
		for _, vuln := range secDBVulnerabilitiesForID {
			// ...is there a fixed in entry? (should always be yes)
			if len(vuln.Fix.Versions) == 0 {
				continue
			}

			// ...is the current package vulnerable?
			vulnerable, err := vuln.Constraint.Satisfied(verObj)
			if err != nil {
				return nil, err
			}

			if vulnerable {
				// if there is at least one vulnerable entry, then all CPE record(s) should be added to the final results
				finalCpeMatches = append(finalCpeMatches, cpeMatchesForID...)
				continue cveLoop
			}
		}
	}
	return finalCpeMatches, nil
}

func deduplicateMatches(secDBMatches, cpeMatches []match.Match) (matches []match.Match) {
	// add additional unique matches from CPE source that is unique from the SecDB matches
	secDBMatchesByID := matchesByID(secDBMatches)
	cpeMatchesByID := matchesByID(cpeMatches)
	for id, cpeMatchesForID := range cpeMatchesByID {
		// by this point all matches have been verified to be vulnerable within the given package version relative to the vulnerability source.
		// now we will add unique CPE candidates that were not found in secdb.
		if _, exists := secDBMatchesByID[id]; !exists {
			// add the new CPE-based record (e.g. NVD) since it was not found in secDB
			matches = append(matches, cpeMatchesForID...)
		}
	}
	return matches
}

func matchesByID(matches []match.Match) map[string][]match.Match {
	var results = make(map[string][]match.Match)
	for _, secDBMatch := range matches {
		results[secDBMatch.Vulnerability.ID] = append(results[secDBMatch.Vulnerability.ID], secDBMatch)
	}
	return results
}

func vulnerabilitiesByID(vulns []vulnerability.Vulnerability) map[string][]vulnerability.Vulnerability {
	var results = make(map[string][]vulnerability.Vulnerability)
	for _, vuln := range vulns {
		results[vuln.ID] = append(results[vuln.ID], vuln)
	}

	return results
}

func (m *Matcher) findApkPackage(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	// find Alpine SecDB matches for the given package name and version
	secDBMatches, err := common.FindMatchesByPackageDistro(store, d, p, m.Type())
	if err != nil {
		return nil, err
	}

	cpeMatches, err := m.cpeMatchesWithoutSecDBFixes(store, d, p)
	if err != nil {
		return nil, err
	}

	var matches []match.Match

	// keep all secdb matches, as this is an authoritative source
	matches = append(matches, secDBMatches...)

	// keep only unique CPE matches
	matches = append(matches, deduplicateMatches(secDBMatches, cpeMatches)...)

	return matches, nil
}

func (m *Matcher) matchBySourceIndirection(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	// build indirect package for matching against source package
	indirectPackage, err := buildIndirectPackage(p)
	if err != nil {
		// If the err is that there no indirect package return empty slice
		if errors.Is(err, errNoIndirectPackage) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to build an indirect package for: %s", p.Name)
	}

	matches, err := m.findApkPackage(store, d, indirectPackage)
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities by apk source indirection: %w", err)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the indirect package)
	// however, we also want to keep the indirect package around for future reference
	for idx := range matches {
		matches[idx].Package = p

		if matches[idx].Type == match.ExactDirectMatch {
			matches[idx].Type = match.ExactIndirectMatch
		}
	}

	return matches, nil
}

// Custom error for when indirect package is not present or is identical to package
var errNoIndirectPackage = errors.New("source package is either identical to pkg or not present")

func buildIndirectPackage(p pkg.Package) (pkg.Package, error) {
	metadata, ok := p.Metadata.(pkg.ApkMetadata)
	// ignore packages without source indirection hints or where source name is identical to package name
	if !ok || metadata.OriginPackage == "" || metadata.OriginPackage == p.Name {
		return pkg.Package{}, errNoIndirectPackage
	}

	var indirectPackage pkg.Package
	err := copier.Copy(&indirectPackage, p)
	if err != nil {
		return pkg.Package{}, fmt.Errorf("failed to copy package: %w", err)
	}

	// use the source package name
	indirectPackage.Name = metadata.OriginPackage

	// For each cpe, replace pkg name with origin and add to set
	cpeStrings := strset.New()
	for _, cpe := range indirectPackage.CPEs {
		updatedCPEString := strings.ReplaceAll(cpe.BindToFmtString(), p.Name, indirectPackage.Name)
		cpeStrings.Add(updatedCPEString)
	}

	// With each entry in set, convert string to CPE and update indirectPackage CPEs
	var updatedCPEs []syftPkg.CPE
	for _, cpeString := range cpeStrings.List() {
		updatedCPE, _ := syftPkg.NewCPE(cpeString)
		updatedCPEs = append(updatedCPEs, updatedCPE)
	}
	indirectPackage.CPEs = updatedCPEs

	return indirectPackage, nil
}
