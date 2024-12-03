package dbsearch

import (
	"sort"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
)

type MatchTableRows []MatchTableRow

type MatchTableRow struct {
	Vulnerability    VulnerabilityInfo     `json:"vulnerability"`
	AffectedPackages []AffectedPackageInfo `json:"packages"`
}

func (m MatchTableRow) Flatten() []AffectedPackageTableRow {
	var rows []AffectedPackageTableRow
	for _, pkg := range m.AffectedPackages {
		rows = append(rows, AffectedPackageTableRow{
			Vulnerability:       m.Vulnerability,
			AffectedPackageInfo: pkg,
		})
	}
	return rows
}

func (m MatchTableRows) Flatten() []AffectedPackageTableRow {
	var rows []AffectedPackageTableRow
	for _, r := range m {
		rows = append(rows, r.Flatten()...)
	}
	return rows
}

func newMatchesRows(affectedPkgs []v6.AffectedPackageHandle, affectedCPEs []v6.AffectedCPEHandle) (rows []MatchTableRow) {
	var affectedPkgsByVuln = make(map[v6.ID][]AffectedPackageInfo)
	var vulnsByID = make(map[v6.ID]v6.VulnerabilityHandle)

	for _, pkg := range affectedPkgs {
		var detail v6.AffectedPackageBlob
		if pkg.BlobValue != nil {
			detail = *pkg.BlobValue
		}
		if pkg.Vulnerability == nil {
			// TODO: handle better
			log.Errorf("affected package record missing vulnerability: %+v", pkg)
			continue
		}
		if _, ok := vulnsByID[pkg.Vulnerability.ID]; !ok {
			vulnsByID[pkg.Vulnerability.ID] = *pkg.Vulnerability
		}

		aff := AffectedPackageInfo{
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
			// TODO: handle better
			log.Errorf("affected CPE record missing vulnerability: %+v", ac)
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
			CPE:    c,
			Detail: detail,
		}

		affectedPkgsByVuln[ac.Vulnerability.ID] = append(affectedPkgsByVuln[ac.Vulnerability.ID], aff)
	}

	for vulnID, vuln := range vulnsByID {
		rows = append(rows, MatchTableRow{
			Vulnerability:    newVulnerabilityInfo(vuln),
			AffectedPackages: affectedPkgsByVuln[vulnID],
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Vulnerability.ID < rows[j].Vulnerability.ID
	})

	return rows
}

func Matches(reader interface {
	v6.AffectedPackageStoreReader
	v6.AffectedCPEStoreReader
}, criteria AffectedPackagesOptions) (MatchTableRows, error) {
	allAffectedPkgs, allAffectedCPEs, err := searchAffectedPackages(reader, criteria)

	return newMatchesRows(allAffectedPkgs, allAffectedCPEs), err
}
