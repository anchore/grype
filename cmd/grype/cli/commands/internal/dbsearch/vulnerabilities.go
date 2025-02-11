package dbsearch

import (
	"errors"
	"fmt"
	"sort"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
)

// Vulnerabilities is the JSON document for the `db search vuln` command
type Vulnerabilities []Vulnerability

// Vulnerability represents the core advisory record for a single known vulnerability from a specific provider.
type Vulnerability struct {
	VulnerabilityInfo `json:",inline"`

	// OperatingSystems is a list of operating systems affected by the vulnerability
	OperatingSystems []OperatingSystem `json:"operating_systems"`

	// AffectedPackages is the number of packages affected by the vulnerability
	AffectedPackages int `json:"affected_packages"`
}

type VulnerabilityInfo struct {
	// TODO: remove this when namespace is no longer used
	Model v6.VulnerabilityHandle `json:"-"` // tracking package handle info is necessary for namespace lookup

	v6.VulnerabilityBlob `json:",inline"`

	// Provider is the upstream data processor (usually Vunnel) that is responsible for vulnerability records. Each provider
	// should be scoped to a specific vulnerability dataset, for instance, the "ubuntu" provider for all records from
	// Canonicals' Ubuntu Security Notices (for all Ubuntu distro versions).
	Provider string `json:"provider"`

	// Status conveys the actionability of the current record (one of "active", "analyzing", "rejected", "disputed")
	Status string `json:"status"`

	// PublishedDate is the date the vulnerability record was first published
	PublishedDate *time.Time `json:"published_date,omitempty"`

	// ModifiedDate is the date the vulnerability record was last modified
	ModifiedDate *time.Time `json:"modified_date,omitempty"`

	// WithdrawnDate is the date the vulnerability record was withdrawn
	WithdrawnDate *time.Time `json:"withdrawn_date,omitempty"`
}

// OperatingSystem represents specific release of an operating system.
type OperatingSystem struct {
	// Name is the operating system family name (e.g. "debian")
	Name string `json:"name"`

	// Version is the semver-ish or codename for the release of the operating system
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
		Model:             vuln,
		VulnerabilityBlob: blob,
		Provider:          vuln.Provider.ID,
		Status:            string(vuln.Status),
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

func FindVulnerabilities(reader interface { //nolint:funlen
	v6.VulnerabilityStoreReader
	v6.AffectedPackageStoreReader
}, config VulnerabilitiesOptions) ([]Vulnerability, error) {
	log.WithFields("vulnSpecs", len(config.Vulnerability)).Debug("fetching vulnerabilities")

	if config.RecordLimit == 0 {
		log.Warn("no record limit set! For queries with large result sets this may result in performance issues")
	}

	var vulns []v6.VulnerabilityHandle
	var limitReached bool
	for _, vulnSpec := range config.Vulnerability {
		vs, err := reader.GetVulnerabilities(&vulnSpec, &v6.GetVulnerabilityOptions{
			Preload: true,
			Limit:   config.RecordLimit,
		})
		if err != nil {
			if !errors.Is(err, v6.ErrLimitReached) {
				return nil, fmt.Errorf("unable to get vulnerabilities: %w", err)
			}
			limitReached = true
			break
		}

		vulns = append(vulns, vs...)
	}

	log.WithFields("vulns", len(vulns)).Debug("fetching affected packages")

	// find all affected packages for this vulnerability, so we can gather os information
	var pairs []vulnerabilityAffectedPackageJoin
	for _, vuln := range vulns {
		affected, fetchErr := reader.GetAffectedPackages(nil, &v6.GetAffectedPackageOptions{
			PreloadOS: true,
			Vulnerabilities: []v6.VulnerabilitySpecifier{
				{
					ID: vuln.ID,
				},
			},
			Limit: config.RecordLimit,
		})
		if fetchErr != nil {
			if !errors.Is(fetchErr, v6.ErrLimitReached) {
				return nil, fmt.Errorf("unable to get affected packages: %w", fetchErr)
			}
			limitReached = true
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

		if errors.Is(fetchErr, v6.ErrLimitReached) {
			break
		}
	}

	var err error
	if limitReached {
		err = v6.ErrLimitReached
	}

	return newVulnerabilityRows(pairs...), err
}
