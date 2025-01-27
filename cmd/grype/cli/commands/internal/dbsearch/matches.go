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

func newMatchesRows(affectedPkgs []v6.AffectedPackageHandle, affectedCPEs []v6.AffectedCPEHandle) (rows []Match, retErr error) {
	var affectedPkgsByVuln = make(map[v6.ID][]AffectedPackageInfo)
	var vulnsByID = make(map[v6.ID]v6.VulnerabilityHandle)

	for i := range affectedPkgs {
		pkg := affectedPkgs[i]
		var detail v6.AffectedPackageBlob
		if pkg.BlobValue != nil {
			detail = *pkg.BlobValue
		}
		if pkg.Vulnerability == nil {
			retErr = multierror.Append(retErr, fmt.Errorf("affected package record missing vulnerability: %+v", pkg))
			continue
		}
		if _, ok := vulnsByID[pkg.Vulnerability.ID]; !ok {
			vulnsByID[pkg.Vulnerability.ID] = *pkg.Vulnerability
		}

		aff := AffectedPackageInfo{
			Model:   &pkg,
			OS:      toOS(pkg.OperatingSystem),
			Package: toPackage(pkg.Package),
			Detail:  detail,
		}

		affectedPkgsByVuln[pkg.Vulnerability.ID] = append(affectedPkgsByVuln[pkg.Vulnerability.ID], aff)
	}

	for _, ac := range affectedCPEs {
		var detail v6.AffectedPackageBlob
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
		}

		aff := AffectedPackageInfo{
			// tracking model information is not possible with CPE handles
			CPE:    c,
			Detail: detail,
		}

		affectedPkgsByVuln[ac.Vulnerability.ID] = append(affectedPkgsByVuln[ac.Vulnerability.ID], aff)
	}

	for vulnID, vuln := range vulnsByID {
		rows = append(rows, Match{
			Vulnerability:    newVulnerabilityInfo(vuln),
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
}, criteria AffectedPackagesOptions) (Matches, error) {
	allAffectedPkgs, allAffectedCPEs, fetchErr := findAffectedPackages(reader, criteria)

	if fetchErr != nil {
		if !errors.Is(fetchErr, v6.ErrLimitReached) {
			return nil, fetchErr
		}
	}

	rows, presErr := newMatchesRows(allAffectedPkgs, allAffectedCPEs)
	if presErr != nil {
		return nil, presErr
	}
	return rows, fetchErr
}
