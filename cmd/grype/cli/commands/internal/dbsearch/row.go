package dbsearch

import (
	"encoding/json"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
)

type Row struct {
	Vulnerability vulnerability          `json:"vulnerability"`
	OS            *OS                    `json:"os,omitempty"`
	Package       *Package               `json:"package,omitempty"`
	CPE           *v6.Cpe                `json:"cpe,omitempty"`
	Detail        v6.AffectedPackageBlob `json:"detail"`
}

type vulnerability struct {
	v6.VulnerabilityBlob `json:",inline"`
	Provider             string     `json:"provider"`
	Status               string     `json:"status"`
	PublishedDate        *time.Time `json:"published_date"`
	ModifiedDate         *time.Time `json:"modified_date"`
	WithdrawnDate        *time.Time `json:"withdrawn_date"`
}

func (r Row) MarshalJSON() ([]byte, error) {
	var cpe string
	if r.CPE != nil {
		cpe = r.CPE.String()
	}
	return json.Marshal(&struct {
		Vulnerability vulnerability          `json:"vulnerability"`
		OS            *OS                    `json:"os,omitempty"`
		Package       *Package               `json:"package,omitempty"`
		CPE           string                 `json:"cpe,omitempty"`
		Detail        v6.AffectedPackageBlob `json:"detail"`
	}{
		Vulnerability: r.Vulnerability,
		OS:            r.OS,
		Package:       r.Package,
		CPE:           cpe,
		Detail:        r.Detail,
	})
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OS struct {
	Family  string `json:"family"`
	Version string `json:"version"`
}

func NewRows(affectedPkgs []v6.AffectedPackageHandle, affectedCPEs []v6.AffectedCPEHandle) []Row {
	var rows []Row
	for _, pkg := range affectedPkgs {
		var detail v6.AffectedPackageBlob
		if pkg.BlobValue != nil {
			detail = *pkg.BlobValue
		}
		rows = append(rows, Row{
			Vulnerability: toVulnerability(pkg.Vulnerability),
			OS:            toOS(pkg.OperatingSystem),
			Package:       toPackage(pkg.Package),
			Detail:        detail,
		})
	}

	for _, ac := range affectedCPEs {
		var detail v6.AffectedPackageBlob
		if ac.BlobValue != nil {
			detail = *ac.BlobValue
		}
		rows = append(rows, Row{
			Vulnerability: toVulnerability(ac.Vulnerability),
			CPE:           ac.CPE,
			Detail:        detail,
		})
	}
	return rows
}

func toVulnerability(vuln *v6.VulnerabilityHandle) vulnerability {
	if vuln == nil {
		return vulnerability{}
	}
	var blob v6.VulnerabilityBlob
	if vuln.BlobValue != nil {
		blob = *vuln.BlobValue
	}
	return vulnerability{
		VulnerabilityBlob: blob,
		Provider:          vuln.Provider.ID,
		Status:            vuln.Status,
		PublishedDate:     vuln.PublishedDate,
		ModifiedDate:      vuln.ModifiedDate,
		WithdrawnDate:     vuln.WithdrawnDate,
	}
}

func toPackage(pkg *v6.Package) *Package {
	if pkg == nil {
		return nil
	}
	return &Package{
		Name:      pkg.Name,
		Ecosystem: pkg.Type,
	}
}

func toOS(os *v6.OperatingSystem) *OS {
	if os == nil {
		return nil
	}
	version := os.VersionNumber()
	if version == "" {
		version = os.Version()
	}

	return &OS{
		Family:  os.Name,
		Version: version,
	}
}
