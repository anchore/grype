package dbsearch

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/hashicorp/go-multierror"

	v6 "github.com/anchore/grype/grype/db/v6"
)

// Matches is the JSON document for the `db search` command
type Matches []Match

// Match represents a pairing of a vulnerability advisory with the packages affected by the vulnerability. When
// unaffected records are requested, a match may only have unaffected packages and an empty list of affected packages.
type Match struct {
	// Vulnerability is the core advisory record for a single known vulnerability from a specific provider.
	Vulnerability VulnerabilityInfo `json:"vulnerability"`

	// AffectedPackages is the list of packages affected by the vulnerability. This is empty when unaffected records were requested and the vulnerability only has unaffected records.
	AffectedPackages []AffectedPackageInfo `json:"packages"`

	// Unaffected is the list of packages explicitly NOT affected by the vulnerability. This is only populated when unaffected records are requested, and is omitted when there are none.
	Unaffected []AffectedPackageInfo `json:"unaffected,omitempty"`
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
				retErr = multierror.Append(retErr, fmt.Errorf("package record missing vulnerability: %+v", pkg))
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
				retErr = multierror.Append(retErr, fmt.Errorf("CPE record missing vulnerability: %+v", ac))
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

	// the same vulnerability ID can come from multiple providers (and records), so break ties to keep the order stable
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].Vulnerability, rows[j].Vulnerability
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		return a.Model.ID < b.Model.ID
	})

	return rows, retErr
}

func FindMatches(reader interface {
	v6.AffectedPackageStoreReader
	v6.AffectedCPEStoreReader
	v6.UnaffectedPackageStoreReader
	v6.UnaffectedCPEStoreReader
	v6.VulnerabilityAliasStoreReader
	v6.VulnerabilityDecoratorStoreReader
}, criteria AffectedPackagesOptions) (Matches, error) {
	if criteria.IncludeAliases {
		expanded, err := expandAliases(reader, criteria.Vulnerability)
		if err != nil {
			return nil, err
		}
		criteria.Vulnerability = expanded
	}

	// unaffected is a record type, not a blob fix state (providers store it as not-affected or as fixed), so asking
	// for the not-affected state means asking for the unaffected records
	wantNotAffected := slices.Contains(criteria.FixedStates, fixStateNotAffected)

	set := affectedRecords
	switch {
	case wantNotAffected && onlyNotAffected(criteria.FixedStates):
		// no affected record can pass the filter, so don't spend the record limit fetching them
		set = unaffectedRecords
	case wantNotAffected || criteria.IncludeUnaffected:
		set = allRecords
	}

	records, fetchErr := findAffectedPackages(reader, criteria, set)

	if fetchErr != nil {
		if !errors.Is(fetchErr, v6.ErrLimitReached) {
			return nil, fetchErr
		}
	}

	if len(criteria.FixedStates) > 0 {
		records.affectedPkgs = filterByFixedStateForPackages(records.affectedPkgs, criteria.FixedStates)
		records.affectedCPEs = filterByFixedStateForCPEs(records.affectedCPEs, criteria.FixedStates)
		if !wantNotAffected {
			// keep unaffected records only as context for the vulnerabilities that still have affected records
			records.keepUnaffectedForAffectedVulnerabilities()
		}
	}

	records.decorate(reader)

	rows, presErr := newMatchesRows(records)
	if presErr != nil {
		return nil, presErr
	}
	return rows, fetchErr
}

// onlyNotAffected is true when every requested fix state is not-affected
func onlyNotAffected(states []string) bool {
	return !slices.ContainsFunc(states, func(s string) bool { return s != fixStateNotAffected })
}
