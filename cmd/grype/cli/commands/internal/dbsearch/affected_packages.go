package dbsearch

import (
	"errors"
	"fmt"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

var ErrNoSearchCriteria = errors.New("must provide at least one of vulnerability or package to search for")

type AffectedPackageTableRow struct {
	Vulnerability       VulnerabilityInfo `json:"vulnerability"`
	AffectedPackageInfo `json:",inline"`
}

type AffectedPackageInfo struct {
	OS      *OS                    `json:"os,omitempty"`
	Package *Package               `json:"package,omitempty"`
	CPE     *CPE                   `json:"cpe,omitempty"`
	Detail  v6.AffectedPackageBlob `json:"detail"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OS struct {
	Family  string `json:"family"`
	Version string `json:"version"`
}

type AffectedPackagesOptions struct {
	Vulnerability v6.VulnerabilitySpecifiers
	Package       v6.PackageSpecifiers
	CPE           v6.PackageSpecifiers
	OS            v6.OSSpecifiers
	RecordLimit   int
}

func newAffectedPackageRows(affectedPkgs []v6.AffectedPackageHandle, affectedCPEs []v6.AffectedCPEHandle) (rows []AffectedPackageTableRow) {
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

		rows = append(rows, AffectedPackageTableRow{
			Vulnerability: newVulnerabilityInfo(*pkg.Vulnerability),
			AffectedPackageInfo: AffectedPackageInfo{
				OS:      toOS(pkg.OperatingSystem),
				Package: toPackage(pkg.Package),
				Detail:  detail,
			},
		})
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

		rows = append(rows, AffectedPackageTableRow{
			Vulnerability: newVulnerabilityInfo(*ac.Vulnerability),
			AffectedPackageInfo: AffectedPackageInfo{
				CPE:    c,
				Detail: detail,
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

func AffectedPackages(reader interface {
	v6.AffectedPackageStoreReader
	v6.AffectedCPEStoreReader
}, criteria AffectedPackagesOptions) ([]AffectedPackageTableRow, error) {
	allAffectedPkgs, allAffectedCPEs, err := searchAffectedPackages(reader, criteria)
	if err != nil {
		return nil, err
	}

	return newAffectedPackageRows(allAffectedPkgs, allAffectedCPEs), nil
}

func searchAffectedPackages(reader interface { //nolint:funlen
	v6.AffectedPackageStoreReader
	v6.AffectedCPEStoreReader
}, config AffectedPackagesOptions) ([]v6.AffectedPackageHandle, []v6.AffectedCPEHandle, error) {
	var allAffectedPkgs []v6.AffectedPackageHandle
	var allAffectedCPEs []v6.AffectedCPEHandle

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

	if len(pkgSpecs) == 0 {
		pkgSpecs = []*v6.PackageSpecifier{nil}
	}

	if len(cpeSpecs) == 0 {
		cpeSpecs = []*v6.PackageSpecifier{nil}
	}

	for i := range pkgSpecs {
		pkgSpec := pkgSpecs[i]

		log.WithFields("vuln", vulnSpecs, "pkg", pkgSpec, "os", osSpecs).Debug("searching for affected packages")

		affectedPkgs, err := reader.GetAffectedPackages(pkgSpec, &v6.GetAffectedPackageOptions{
			PreloadOS:            true,
			PreloadPackage:       true,
			PreloadPackageCPEs:   false,
			PreloadVulnerability: true,
			PreloadBlob:          true,
			OSs:                  osSpecs,
			Vulnerabilities:      vulnSpecs,
			Limit:                config.RecordLimit,
		})

		allAffectedPkgs = append(allAffectedPkgs, affectedPkgs...)

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
				PreloadCPE:           true,
				PreloadVulnerability: true,
				PreloadBlob:          true,
				Vulnerabilities:      vulnSpecs,
				Limit:                config.RecordLimit,
			})

			allAffectedCPEs = append(allAffectedCPEs, affectedCPEs...)

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
