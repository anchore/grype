package dbsearch

import (
	"fmt"
	"sort"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
)

// Vulnerabilities is the JSON document for the `db search vuln` command
type Vulnerabilities []Vulnerability

type Vulnerability struct {
	VulnerabilityInfo `json:",inline"`
	OperatingSystems  []OperatingSystem `json:"operating_systems"`
	AffectedPackages  int               `json:"affected_packages"`
}

type VulnerabilityInfo struct {
	v6.VulnerabilityBlob `json:",inline"`
	Provider             string     `json:"provider"`
	Status               string     `json:"status"`
	PublishedDate        *time.Time `json:"published_date,omitempty"`
	ModifiedDate         *time.Time `json:"modified_date,omitempty"`
	WithdrawnDate        *time.Time `json:"withdrawn_date,omitempty"`
}

type OperatingSystem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type vulnerabilityAffectedPackageJoin struct {
	Vulnerability    v6.VulnerabilityHandle
	OperatingSystems []v6.OperatingSystem
	AffectedPackages int
}

type VulnerabilitiesOptions struct {
	Vulnerability v6.VulnerabilitySpecifiers
	RecordLimit   int
}

func newVulnerabilityRows(vaps ...vulnerabilityAffectedPackageJoin) (rows []Vulnerability) {
	for _, vap := range vaps {
		rows = append(rows, newVulnerabilityRow(vap.Vulnerability, vap.AffectedPackages, vap.OperatingSystems))
	}
	return rows
}

func newVulnerabilityRow(vuln v6.VulnerabilityHandle, apCount int, operatingSystems []v6.OperatingSystem) Vulnerability {
	return Vulnerability{
		VulnerabilityInfo: newVulnerabilityInfo(vuln),
		OperatingSystems:  newOperatingSystems(operatingSystems),
		AffectedPackages:  apCount,
	}
}

func newVulnerabilityInfo(vuln v6.VulnerabilityHandle) VulnerabilityInfo {
	var blob v6.VulnerabilityBlob
	if vuln.BlobValue != nil {
		blob = *vuln.BlobValue
	}
	return VulnerabilityInfo{
		VulnerabilityBlob: blob,
		Provider:          vuln.Provider.ID,
		Status:            vuln.Status,
		PublishedDate:     vuln.PublishedDate,
		ModifiedDate:      vuln.ModifiedDate,
		WithdrawnDate:     vuln.WithdrawnDate,
	}
}

func newOperatingSystems(oss []v6.OperatingSystem) (os []OperatingSystem) {
	for _, o := range oss {
		os = append(os, OperatingSystem{
			Name:    o.Name,
			Version: o.Version(),
		})
	}
	return os
}

func FindVulnerabilities(reader interface {
	v6.VulnerabilityStoreReader
	v6.AffectedPackageStoreReader
}, config VulnerabilitiesOptions) ([]Vulnerability, error) {
	log.WithFields("vulnSpecs", len(config.Vulnerability)).Debug("fetching vulnerabilities")

	if config.RecordLimit == 0 {
		log.Warn("no record limit set! For queries with large result sets this may result in performance issues")
	}

	var vulns []v6.VulnerabilityHandle
	for i := range config.Vulnerability {
		vulnSpec := config.Vulnerability[i]
		vs, err := reader.GetVulnerabilities(&vulnSpec, &v6.GetVulnerabilityOptions{
			Preload: true,
			Limit:   config.RecordLimit,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to get vulnerabilities: %w", err)
		}

		vulns = append(vulns, vs...)
	}

	log.WithFields("vulns", len(vulns)).Debug("fetching affected packages")

	// find all affected packages for this vulnerability, so we can gather os information
	var pairs []vulnerabilityAffectedPackageJoin
	for _, vuln := range vulns {
		affected, err := reader.GetAffectedPackages(nil, &v6.GetAffectedPackageOptions{
			PreloadOS: true,
			Vulnerabilities: []v6.VulnerabilitySpecifier{
				{
					ID: vuln.ID,
				},
			},
			Limit: config.RecordLimit,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to get affected packages: %w", err)
		}

		distros := make(map[v6.ID]v6.OperatingSystem)
		for _, a := range affected {
			if a.OperatingSystem != nil {
				if _, ok := distros[a.OperatingSystem.ID]; !ok {
					distros[a.OperatingSystem.ID] = *a.OperatingSystem
				}
			}
		}

		var distrosSlice []v6.OperatingSystem
		for _, d := range distros {
			distrosSlice = append(distrosSlice, d)
		}

		sort.Slice(distrosSlice, func(i, j int) bool {
			return distrosSlice[i].ID < distrosSlice[j].ID
		})

		pairs = append(pairs, vulnerabilityAffectedPackageJoin{
			Vulnerability:    vuln,
			OperatingSystems: distrosSlice,
			AffectedPackages: len(affected),
		})
	}

	return newVulnerabilityRows(pairs...), nil
}
