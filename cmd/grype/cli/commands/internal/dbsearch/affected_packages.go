package dbsearch

import (
	"errors"
	"fmt"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

var ErrNoSearchCriteria = errors.New("must provide at least one of vulnerability or package to search for")

// AffectedPackage represents a package affected by a vulnerability
type AffectedPackage struct {
	// Vulnerability is the core advisory record for a single known vulnerability from a specific provider.
	Vulnerability VulnerabilityInfo `json:"vulnerability"`

	// AffectedPackageInfo is the detailed information about the affected package
	AffectedPackageInfo `json:",inline"`
}

type AffectedPackageInfo struct {
	// TODO: remove this when namespace is no longer used
	Model *v6.AffectedPackageHandle `json:"-"` // tracking package handle info is necessary for namespace lookup (note CPE handles are not tracked)

	// OS identifies the operating system release that the affected package is released for
	OS *OperatingSystem `json:"os,omitempty"`

	// Package identifies the name of the package in a specific ecosystem affected by the vulnerability
	Package *Package `json:"package,omitempty"`

	// CPE is a Common Platform Enumeration that is affected by the vulnerability
	CPE *CPE `json:"cpe,omitempty"`

	// Namespace is a holdover value from the v5 DB schema that combines provider and search methods into a single value
	//
	// Deprecated: this field will be removed in a later version of the search schema
	Namespace string `json:"namespace"`

	// Detail is the detailed information about the affected package
	Detail v6.PackageBlob `json:"detail"`
}

// Package represents a package name within a known ecosystem, such as "python" or "golang".
type Package struct {
	// Name is the name of the package within the ecosystem
	Name string `json:"name"`

	// Ecosystem is the tooling and language ecosystem that the package is released within
	Ecosystem string `json:"ecosystem"`
}

// CPE is a Common Platform Enumeration that identifies a package
type CPE v6.Cpe

func (c *CPE) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", c.String())), nil
}

func (c *CPE) String() string {
	if c == nil {
		return ""
	}

	formattedCPE := cpe.CPE{
		Attributes: cpe.Attributes{
			Part:      c.Part,
			Vendor:    c.Vendor,
			Product:   c.Product,
			Version:   "*",
			Update:    "*",
			Edition:   c.Edition,
			SWEdition: c.SoftwareEdition,
			TargetSW:  c.TargetSoftware,
			TargetHW:  c.TargetHardware,
			Other:     c.Other,
			Language:  c.Language,
		},
		Source: "",
	}

	return formattedCPE.Attributes.String()
}

type AffectedPackagesOptions struct {
	Vulnerability         v6.VulnerabilitySpecifiers
	Package               v6.PackageSpecifiers
	CPE                   v6.PackageSpecifiers
	OS                    v6.OSSpecifiers
	AllowBroadCPEMatching bool
	RecordLimit           int
	FixedStates           []string
}

type affectedPackageWithDecorations struct {
	v6.AffectedPackageHandle
	vulnerabilityDecorations
}

func (a *affectedPackageWithDecorations) getCVEs() []string {
	if a == nil {
		return nil
	}
	return getCVEs(a.Vulnerability)
}

func (a *affectedPackageWithDecorations) info() AffectedPackageInfo {
	var detail v6.PackageBlob
	if a.BlobValue != nil {
		detail = *a.BlobValue
	}
	return AffectedPackageInfo{
		Model:     &a.AffectedPackageHandle,
		OS:        toOS(a.OperatingSystem),
		Package:   toPackage(a.Package),
		Namespace: v6.MimicV5Namespace(a.Vulnerability, &a.AffectedPackageHandle),
		Detail:    detail,
	}
}

type affectedCPEWithDecorations struct {
	v6.AffectedCPEHandle
	vulnerabilityDecorations
}

func (a *affectedCPEWithDecorations) getCVEs() []string {
	if a == nil {
		return nil
	}
	return getCVEs(a.Vulnerability)
}

func (a *affectedCPEWithDecorations) info() AffectedPackageInfo {
	var detail v6.PackageBlob
	if a.BlobValue != nil {
		detail = *a.BlobValue
	}

	var c *CPE
	if a.CPE != nil {
		cv := CPE(*a.CPE)
		c = &cv
	}

	// tracking model information is not possible with CPE handles
	return AffectedPackageInfo{
		CPE:       c,
		Namespace: v6.MimicV5Namespace(a.Vulnerability, nil), // no affected package will default to NVD
		Detail:    detail,
	}
}

func newAffectedPackageRows(affectedPkgs []affectedPackageWithDecorations, affectedCPEs []affectedCPEWithDecorations) (rows []AffectedPackage) {
	for i := range affectedPkgs {
		pkg := affectedPkgs[i]
		if pkg.Vulnerability == nil {
			log.Errorf("affected package record missing vulnerability: %+v", pkg)
			continue
		}

		rows = append(rows, AffectedPackage{
			Vulnerability:       newVulnerabilityInfo(*pkg.Vulnerability, pkg.vulnerabilityDecorations),
			AffectedPackageInfo: pkg.info(),
		})
	}

	for _, ac := range affectedCPEs {
		if ac.Vulnerability == nil {
			log.Errorf("affected CPE record missing vulnerability: %+v", ac)
			continue
		}

		rows = append(rows, AffectedPackage{
			Vulnerability:       newVulnerabilityInfo(*ac.Vulnerability, ac.vulnerabilityDecorations),
			AffectedPackageInfo: ac.info(),
		})
	}

	return rows
}

func toPackage(pkg *v6.Package) *Package {
	if pkg == nil {
		return nil
	}
	return &Package{
		Name:      pkg.Name,
		Ecosystem: pkg.Ecosystem,
	}
}

func toOS(os *v6.OperatingSystem) *OperatingSystem {
	if os == nil {
		return nil
	}

	return &OperatingSystem{
		Name:    os.Name,
		Version: os.Version(),
	}
}

// packageRecords are the package and CPE records found by a search, unaffected records are converted to the
// affected handle types but are kept separate from the affected records
type packageRecords struct {
	affectedPkgs   []affectedPackageWithDecorations
	affectedCPEs   []affectedCPEWithDecorations
	unaffectedPkgs []affectedPackageWithDecorations
	unaffectedCPEs []affectedCPEWithDecorations
}

func FindAffectedPackages(reader interface {
	v6.AffectedPackageStoreReader
	v6.AffectedCPEStoreReader
	v6.UnaffectedPackageStoreReader
	v6.UnaffectedCPEStoreReader
	v6.VulnerabilityDecoratorStoreReader
}, criteria AffectedPackagesOptions,
) ([]AffectedPackage, error) {
	records, err := findAffectedPackages(reader, criteria)
	if err != nil {
		return nil, err
	}

	if len(criteria.FixedStates) > 0 {
		records.affectedPkgs = filterByFixedStateForPackages(records.affectedPkgs, criteria.FixedStates)
		records.affectedCPEs = filterByFixedStateForCPEs(records.affectedCPEs, criteria.FixedStates)
	}

	// unaffected records are only reported by matches, which keep them separate from the affected packages
	return newAffectedPackageRows(records.affectedPkgs, records.affectedCPEs), nil
}

func findAffectedPackages(reader interface { //nolint:funlen,gocognit,gocyclo
	v6.AffectedPackageStoreReader
	v6.AffectedCPEStoreReader
	v6.UnaffectedPackageStoreReader
	v6.UnaffectedCPEStoreReader
	v6.VulnerabilityDecoratorStoreReader
}, config AffectedPackagesOptions,
) (packageRecords, error) {
	var records packageRecords

	pkgSpecs := config.Package
	cpeSpecs := config.CPE
	osSpecs := config.OS
	vulnSpecs := config.Vulnerability

	if config.RecordLimit == 0 {
		log.Warn("no record limit set! For queries with large result sets this may result in performance issues")
	}

	if len(vulnSpecs) == 0 && len(pkgSpecs) == 0 && len(cpeSpecs) == 0 {
		return packageRecords{}, ErrNoSearchCriteria
	}

	// don't allow for searching by any package AND any CPE AND any vulnerability AND any OS. Since these searches
	// are oriented by primarily package, we only want to have ANY package/CPE when there is a vulnerability or OS specified.
	if len(vulnSpecs) > 0 || !osSpecs.IsAny() {
		if len(pkgSpecs) == 0 {
			pkgSpecs = []*v6.PackageSpecifier{v6.AnyPackageSpecified}
		}

		if len(cpeSpecs) == 0 {
			cpeSpecs = []*v6.PackageSpecifier{v6.AnyPackageSpecified}
		}
	}

	// we have multiple return points that return actual values, using a defer to decorate any given results
	// ensures that all paths are handled the same way.
	defer func() {
		for _, pkgs := range [][]affectedPackageWithDecorations{records.affectedPkgs, records.unaffectedPkgs} {
			for i := range pkgs {
				decorateVulnerabilities(reader, &pkgs[i])
			}
		}

		for _, cpes := range [][]affectedCPEWithDecorations{records.affectedCPEs, records.unaffectedCPEs} {
			for i := range cpes {
				decorateVulnerabilities(reader, &cpes[i])
			}
		}
	}()

	for i := range pkgSpecs {
		pkgSpec := pkgSpecs[i]

		log.WithFields("vuln", vulnSpecs, "pkg", pkgSpec, "os", osSpecs).Debug("searching for affected packages")

		affectedPkgs, err := reader.GetAffectedPackages(pkgSpec, &v6.GetPackageOptions{
			PreloadOS:             true,
			PreloadPackage:        true,
			PreloadPackageCPEs:    false,
			PreloadVulnerability:  true,
			PreloadBlob:           true,
			OSs:                   osSpecs,
			Vulnerabilities:       vulnSpecs,
			AllowBroadCPEMatching: config.AllowBroadCPEMatching,
			Limit:                 config.RecordLimit,
		})

		for i := range affectedPkgs {
			records.affectedPkgs = append(records.affectedPkgs, affectedPackageWithDecorations{
				AffectedPackageHandle: affectedPkgs[i],
			})
		}

		if err != nil {
			if errors.Is(err, v6.ErrLimitReached) {
				return records, err
			}
			return packageRecords{}, fmt.Errorf("unable to get affected packages for %s: %w", vulnSpecs, err)
		}

		unaffectedPkgs, err := reader.GetUnaffectedPackages(pkgSpec, &v6.GetPackageOptions{
			PreloadOS:             true,
			PreloadPackage:        true,
			PreloadPackageCPEs:    false,
			PreloadVulnerability:  true,
			PreloadBlob:           true,
			OSs:                   osSpecs,
			Vulnerabilities:       vulnSpecs,
			AllowBroadCPEMatching: config.AllowBroadCPEMatching,
			Limit:                 config.RecordLimit,
		})

		for i := range unaffectedPkgs {
			records.unaffectedPkgs = append(records.unaffectedPkgs, affectedPackageWithDecorations{
				AffectedPackageHandle: v6.AffectedPackageHandle(unaffectedPkgs[i]),
			})
		}

		if err != nil {
			if errors.Is(err, v6.ErrLimitReached) {
				return records, err
			}
			return packageRecords{}, fmt.Errorf("unable to get unaffected packages for %s: %w", vulnSpecs, err)
		}
	}

	if osSpecs.IsAny() {
		for i := range cpeSpecs {
			cpeSpec := cpeSpecs[i]
			var searchCPE *cpe.Attributes
			if cpeSpec != nil {
				searchCPE = cpeSpec.CPE
			}

			log.WithFields("vuln", vulnSpecs, "cpe", cpeSpec).Debug("searching for affected packages")

			affectedCPEs, err := reader.GetAffectedCPEs(searchCPE, &v6.GetCPEOptions{
				PreloadCPE:            true,
				PreloadVulnerability:  true,
				PreloadBlob:           true,
				Vulnerabilities:       vulnSpecs,
				AllowBroadCPEMatching: config.AllowBroadCPEMatching,
				Limit:                 config.RecordLimit,
			})

			for i := range affectedCPEs {
				records.affectedCPEs = append(records.affectedCPEs, affectedCPEWithDecorations{
					AffectedCPEHandle: affectedCPEs[i],
				})
			}

			if err != nil {
				if errors.Is(err, v6.ErrLimitReached) {
					return records, err
				}
				return packageRecords{}, fmt.Errorf("unable to get affected cpes for %s: %w", vulnSpecs, err)
			}

			unaffectedCPEs, err := reader.GetUnaffectedCPEs(searchCPE, &v6.GetCPEOptions{
				PreloadCPE:            true,
				PreloadVulnerability:  true,
				PreloadBlob:           true,
				Vulnerabilities:       vulnSpecs,
				AllowBroadCPEMatching: config.AllowBroadCPEMatching,
				Limit:                 config.RecordLimit,
			})

			for i := range unaffectedCPEs {
				records.unaffectedCPEs = append(records.unaffectedCPEs, affectedCPEWithDecorations{
					AffectedCPEHandle: v6.AffectedCPEHandle(unaffectedCPEs[i]),
				})
			}

			if err != nil {
				if errors.Is(err, v6.ErrLimitReached) {
					return records, err
				}
				return packageRecords{}, fmt.Errorf("unable to get unaffected cpes for %s: %w", vulnSpecs, err)
			}
		}
	}

	return records, nil
}
