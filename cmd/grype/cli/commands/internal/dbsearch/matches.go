package dbsearch

import (
	"errors"
	"fmt"
	"sort"

	"github.com/hashicorp/go-multierror"

	v6 "github.com/anchore/grype/grype/db/v6"
)

// Matches is the JSON document for the `db search` command
type Matches []Match

// Match represents a pairing of a vulnerability advisory with the packages affected by the vulnerability.
type Match struct {
	// Vulnerability is the core advisory record for a single known vulnerability from a specific provider.
	Vulnerability VulnerabilityInfo `json:"vulnerability"`

	// AffectedPackages is the list of packages affected by the vulnerability.
	AffectedPackages []AffectedPackageInfo `json:"packages"`
}

func (m Match) Flatten() []AffectedPackage {
	var rows []AffectedPackage
	for _, pkg := range m.AffectedPackages {
		rows = append(rows, AffectedPackage{
			Vulnerability:       m.Vulnerability,
			AffectedPackageInfo: pkg,
		})
	}
	return rows
}

func (m Matches) Flatten() []AffectedPackage {
	var rows []AffectedPackage
	for _, r := range m {
		rows = append(rows, r.Flatten()...)
	}
	return rows
}

func newMatchesRows(affectedPkgs []affectedPackageWithDecorations, affectedCPEs []affectedCPEWithDecorations) (rows []Match, retErr error) { // nolint:funlen
	var affectedPkgsByVuln = make(map[v6.ID][]AffectedPackageInfo)
	var vulnsByID = make(map[v6.ID]v6.VulnerabilityHandle)
	var decorationsByID = make(map[v6.ID]vulnerabilityDecorations)

	for i := range affectedPkgs {
		pkg := affectedPkgs[i]
		var detail v6.PackageBlob
		if pkg.BlobValue != nil {
			detail = *pkg.BlobValue
		}
		if pkg.Vulnerability == nil {
			retErr = multierror.Append(retErr, fmt.Errorf("affected package record missing vulnerability: %+v", pkg))
			continue
		}
		if _, ok := vulnsByID[pkg.Vulnerability.ID]; !ok {
			vulnsByID[pkg.Vulnerability.ID] = *pkg.Vulnerability
			decorationsByID[pkg.Vulnerability.ID] = pkg.vulnerabilityDecorations
		}

		aff := AffectedPackageInfo{
			Model:     &pkg.AffectedPackageHandle,
			OS:        toOS(pkg.OperatingSystem),
			Package:   toPackage(pkg.Package),
			Namespace: v6.MimicV5Namespace(pkg.Vulnerability, &pkg.AffectedPackageHandle),
			Detail:    detail,
		}

		affectedPkgsByVuln[pkg.Vulnerability.ID] = append(affectedPkgsByVuln[pkg.Vulnerability.ID], aff)
	}

	for _, ac := range affectedCPEs {
		var detail v6.PackageBlob
		if ac.BlobValue != nil {
			detail = *ac.BlobValue
		}
		if ac.Vulnerability == nil {
			retErr = multierror.Append(retErr, fmt.Errorf("affected CPE record missing vulnerability: %+v", ac))
			continue
		}

		var c *CPE
		if ac.CPE != nil {
			cv := CPE(*ac.CPE)
			c = &cv
		}

		if _, ok := vulnsByID[ac.Vulnerability.ID]; !ok {
			vulnsByID[ac.Vulnerability.ID] = *ac.Vulnerability
			decorationsByID[ac.Vulnerability.ID] = ac.vulnerabilityDecorations
		}

		aff := AffectedPackageInfo{
			// tracking model information is not possible with CPE handles
			CPE:       c,
			Namespace: v6.MimicV5Namespace(ac.Vulnerability, nil), // no affected package will default to NVD
			Detail:    detail,
		}

		affectedPkgsByVuln[ac.Vulnerability.ID] = append(affectedPkgsByVuln[ac.Vulnerability.ID], aff)
	}

	for vulnID, vuln := range vulnsByID {
		rows = append(rows, Match{
			Vulnerability:    newVulnerabilityInfo(vuln, decorationsByID[vulnID]),
			AffectedPackages: affectedPkgsByVuln[vulnID],
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Vulnerability.ID < rows[j].Vulnerability.ID
	})

	return rows, retErr
}

func FindMatches(reader interface {
	v6.AffectedPackageStoreReader
	v6.AffectedCPEStoreReader
	v6.VulnerabilityDecoratorStoreReader
}, criteria AffectedPackagesOptions) (Matches, error) {
	allAffectedPkgs, allAffectedCPEs, fetchErr := findAffectedPackages(reader, criteria)

	if fetchErr != nil {
		if !errors.Is(fetchErr, v6.ErrLimitReached) {
			return nil, fetchErr
		}
	}

	if len(criteria.FixedStates) > 0 {
		allAffectedPkgs = filterByFixedState(allAffectedPkgs, criteria.FixedStates)
		allAffectedCPEs = filterCPEsByFixedState(allAffectedCPEs, criteria.FixedStates)
	}

	rows, presErr := newMatchesRows(allAffectedPkgs, allAffectedCPEs)
	if presErr != nil {
		return nil, presErr
	}
	return rows, fetchErr
}

func filterByFixedState(packages []affectedPackageWithDecorations, fixedStates []string) []affectedPackageWithDecorations {
	if len(fixedStates) == 0 {
		return packages
	}

	stateSet := make(map[string]bool)
	for _, state := range fixedStates {
		stateSet[state] = true
	}

	var filtered []affectedPackageWithDecorations
	for _, pkg := range packages {
		if pkg.BlobValue == nil {
			continue
		}

		fixState := getFixStateFromBlob(pkg.BlobValue)
		if stateSet[fixState] {
			filtered = append(filtered, pkg)
		}
	}

	return filtered
}

func filterCPEsByFixedState(cpes []affectedCPEWithDecorations, fixedStates []string) []affectedCPEWithDecorations {
	if len(fixedStates) == 0 {
		return cpes
	}

	stateSet := make(map[string]bool)
	for _, state := range fixedStates {
		stateSet[state] = true
	}

	var filtered []affectedCPEWithDecorations
	for _, cpe := range cpes {
		if cpe.BlobValue == nil {
			continue
		}

		fixState := getFixStateFromBlob(cpe.BlobValue)
		if stateSet[fixState] {
			filtered = append(filtered, cpe)
		}
	}

	return filtered
}

func getFixStateFromBlob(blob *v6.PackageBlob) string {
	if blob == nil {
		return "unknown"
	}

	hasFixed := false
	hasNotFixed := false
	hasWontFix := false

	for _, r := range blob.Ranges {
		if r.Fix == nil {
			continue
		}
		switch r.Fix.State {
		case v6.FixedStatus:
			hasFixed = true
		case v6.WontFixStatus:
			hasWontFix = true
		case v6.NotFixedStatus:
			hasNotFixed = true
		}
	}

	if hasFixed {
		return "fixed"
	}
	if hasWontFix {
		return "wont-fix"
	}
	if hasNotFixed {
		return "not-fixed"
	}

	return "unknown"
}
