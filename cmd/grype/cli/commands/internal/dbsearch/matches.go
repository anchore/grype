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

	// Unaffected is the list of packages explicitly NOT affected by the vulnerability.
	Unaffected []AffectedPackageInfo `json:"unaffected,omitempty"`
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

func newMatchesRows(records packageRecords) (rows []Match, retErr error) {
	var vulnsByID = make(map[v6.ID]v6.VulnerabilityHandle)
	var decorationsByID = make(map[v6.ID]vulnerabilityDecorations)

	// infoByVuln returns the package and CPE record details grouped by vulnerability, tracking each vulnerability seen
	infoByVuln := func(pkgs []affectedPackageWithDecorations, cpes []affectedCPEWithDecorations) map[v6.ID][]AffectedPackageInfo {
		var byVuln = make(map[v6.ID][]AffectedPackageInfo)

		for i := range pkgs {
			pkg := pkgs[i]
			if pkg.Vulnerability == nil {
				retErr = multierror.Append(retErr, fmt.Errorf("affected package record missing vulnerability: %+v", pkg))
				continue
			}
			if _, ok := vulnsByID[pkg.Vulnerability.ID]; !ok {
				vulnsByID[pkg.Vulnerability.ID] = *pkg.Vulnerability
				decorationsByID[pkg.Vulnerability.ID] = pkg.vulnerabilityDecorations
			}

			byVuln[pkg.Vulnerability.ID] = append(byVuln[pkg.Vulnerability.ID], pkg.info())
		}

		for _, ac := range cpes {
			if ac.Vulnerability == nil {
				retErr = multierror.Append(retErr, fmt.Errorf("affected CPE record missing vulnerability: %+v", ac))
				continue
			}

			if _, ok := vulnsByID[ac.Vulnerability.ID]; !ok {
				vulnsByID[ac.Vulnerability.ID] = *ac.Vulnerability
				decorationsByID[ac.Vulnerability.ID] = ac.vulnerabilityDecorations
			}

			byVuln[ac.Vulnerability.ID] = append(byVuln[ac.Vulnerability.ID], ac.info())
		}

		return byVuln
	}

	affectedByVuln := infoByVuln(records.affectedPkgs, records.affectedCPEs)
	unaffectedByVuln := infoByVuln(records.unaffectedPkgs, records.unaffectedCPEs)

	for vulnID, vuln := range vulnsByID {
		affected := affectedByVuln[vulnID]
		if affected == nil {
			// packages is always present in the output, even when there are only unaffected records
			affected = []AffectedPackageInfo{}
		}

		rows = append(rows, Match{
			Vulnerability:    newVulnerabilityInfo(vuln, decorationsByID[vulnID]),
			AffectedPackages: affected,
			Unaffected:       unaffectedByVuln[vulnID],
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
	v6.UnaffectedPackageStoreReader
	v6.UnaffectedCPEStoreReader
	v6.VulnerabilityDecoratorStoreReader
}, criteria AffectedPackagesOptions) (Matches, error) {
	records, fetchErr := findAffectedPackages(reader, criteria)

	if fetchErr != nil {
		if !errors.Is(fetchErr, v6.ErrLimitReached) {
			return nil, fetchErr
		}
	}

	if len(criteria.FixedStates) > 0 {
		records.affectedPkgs = filterByFixedStateForPackages(records.affectedPkgs, criteria.FixedStates)
		records.affectedCPEs = filterByFixedStateForCPEs(records.affectedCPEs, criteria.FixedStates)
		records.unaffectedPkgs = filterByFixedStateForPackages(records.unaffectedPkgs, criteria.FixedStates)
		records.unaffectedCPEs = filterByFixedStateForCPEs(records.unaffectedCPEs, criteria.FixedStates)
	}

	rows, presErr := newMatchesRows(records)
	if presErr != nil {
		return nil, presErr
	}
	return rows, fetchErr
}
