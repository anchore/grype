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
	// Deprecated: this field will be removed in a later version of the search schema
	Namespace string `json:"namespace"`

	// Detail is the detailed information about the affected package
	Detail v6.AffectedPackageBlob `json:"detail"`
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

	return v6.Cpe(*c).String()
}

type AffectedPackagesOptions struct {
	Vulnerability         v6.VulnerabilitySpecifiers
	Package               v6.PackageSpecifiers
	CPE                   v6.PackageSpecifiers
	OS                    v6.OSSpecifiers
	AllowBroadCPEMatching bool
	RecordLimit           int
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

func newAffectedPackageRows(affectedPkgs []affectedPackageWithDecorations, affectedCPEs []affectedCPEWithDecorations) (rows []AffectedPackage) {
	for i := range affectedPkgs {
		pkg := affectedPkgs[i]
		var detail v6.AffectedPackageBlob
		if pkg.BlobValue != nil {
			detail = *pkg.BlobValue
		}
		if pkg.Vulnerability == nil {
			log.Errorf("affected package record missing vulnerability: %+v", pkg)
			continue
		}

		rows = append(rows, AffectedPackage{
			Vulnerability: newVulnerabilityInfo(*pkg.Vulnerability, pkg.vulnerabilityDecorations),
			AffectedPackageInfo: AffectedPackageInfo{
				Model:     &pkg.AffectedPackageHandle,
				OS:        toOS(pkg.OperatingSystem),
				Package:   toPackage(pkg.Package),
				Namespace: v6.MimicV5Namespace(pkg.Vulnerability, &pkg.AffectedPackageHandle),
				Detail:    detail,
			},
		})
	}

	for _, ac := range affectedCPEs {
		var detail v6.AffectedPackageBlob
		if ac.BlobValue != nil {
			detail = *ac.BlobValue
		}
		if ac.Vulnerability == nil {
			log.Errorf("affected CPE record missing vulnerability: %+v", ac)
			continue
		}

		var c *CPE
		if ac.CPE != nil {
			cv := CPE(*ac.CPE)
			c = &cv
		}

		rows = append(rows, AffectedPackage{
			// tracking model information is not possible with CPE handles
			Vulnerability: newVulnerabilityInfo(*ac.Vulnerability, ac.vulnerabilityDecorations),
			AffectedPackageInfo: AffectedPackageInfo{
				CPE:       c,
				Namespace: v6.MimicV5Namespace(ac.Vulnerability, nil), // no affected package will default to NVD
				Detail:    detail,
			},
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
	version := os.VersionNumber()
	if version == "" {
		version = os.Version()
	}

	return &OperatingSystem{
		Name:    os.Name,
		Version: version,
	}
}

func FindAffectedPackages(reader interface {
	v6.AffectedPackageStoreReader
	v6.AffectedCPEStoreReader
	v6.VulnerabilityDecoratorStoreReader
}, criteria AffectedPackagesOptions) ([]AffectedPackage, error) {
	allAffectedPkgs, allAffectedCPEs, err := findAffectedPackages(reader, criteria)
	if err != nil {
		return nil, err
	}

	return newAffectedPackageRows(allAffectedPkgs, allAffectedCPEs), nil
}

func findAffectedPackages(reader interface { //nolint:funlen,gocognit
	v6.AffectedPackageStoreReader
	v6.AffectedCPEStoreReader
	v6.VulnerabilityDecoratorStoreReader
}, config AffectedPackagesOptions) ([]affectedPackageWithDecorations, []affectedCPEWithDecorations, error) {
	var allAffectedPkgs []affectedPackageWithDecorations
	var allAffectedCPEs []affectedCPEWithDecorations

	pkgSpecs := config.Package
	cpeSpecs := config.CPE
	osSpecs := config.OS
	vulnSpecs := config.Vulnerability

	if config.RecordLimit == 0 {
		log.Warn("no record limit set! For queries with large result sets this may result in performance issues")
	}

	if len(vulnSpecs) == 0 && len(pkgSpecs) == 0 && len(cpeSpecs) == 0 {
		return nil, nil, ErrNoSearchCriteria
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
		for i := range allAffectedPkgs {
			if err := decorateVulnerabilities(reader, &allAffectedPkgs[i]); err != nil {
				log.WithFields("error", err).Debug("unable to decorate vulnerability on affected package")
			}
		}

		for i := range allAffectedCPEs {
			if err := decorateVulnerabilities(reader, &allAffectedCPEs[i]); err != nil {
				log.WithFields("error", err).Debug("unable to decorate vulnerability on affected CPE")
			}
		}
	}()

	for i := range pkgSpecs {
		pkgSpec := pkgSpecs[i]

		log.WithFields("vuln", vulnSpecs, "pkg", pkgSpec, "os", osSpecs).Debug("searching for affected packages")

		affectedPkgs, err := reader.GetAffectedPackages(pkgSpec, &v6.GetAffectedPackageOptions{
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
			allAffectedPkgs = append(allAffectedPkgs, affectedPackageWithDecorations{
				AffectedPackageHandle: affectedPkgs[i],
			})
		}

		if err != nil {
			if errors.Is(err, v6.ErrLimitReached) {
				return allAffectedPkgs, allAffectedCPEs, err
			}
			return nil, nil, fmt.Errorf("unable to get affected packages for %s: %w", vulnSpecs, err)
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

			affectedCPEs, err := reader.GetAffectedCPEs(searchCPE, &v6.GetAffectedCPEOptions{
				PreloadCPE:            true,
				PreloadVulnerability:  true,
				PreloadBlob:           true,
				Vulnerabilities:       vulnSpecs,
				AllowBroadCPEMatching: config.AllowBroadCPEMatching,
				Limit:                 config.RecordLimit,
			})

			for i := range affectedCPEs {
				allAffectedCPEs = append(allAffectedCPEs, affectedCPEWithDecorations{
					AffectedCPEHandle: affectedCPEs[i],
				})
			}

			if err != nil {
				if errors.Is(err, v6.ErrLimitReached) {
					return allAffectedPkgs, allAffectedCPEs, err
				}
				return nil, nil, fmt.Errorf("unable to get affected cpes for %s: %w", vulnSpecs, err)
			}
		}
	}

	return allAffectedPkgs, allAffectedCPEs, nil
}
