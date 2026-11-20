package dbsearch

import (
	"errors"
	"fmt"
	"slices"
	"strings"

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
	// note: for unaffected records this is the unaffected handle converted to the affected handle type (they share an
	// underlying type), so don't use the type of this field to tell affected and unaffected records apart
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

	// IncludeUnaffected also fetches unaffected package and CPE records. These are fetched after the affected records
	// with the same per-query RecordLimit, and are skipped once the affected records reach the limit.
	IncludeUnaffected bool

	// IncludeAliases expands each named vulnerability to the vulnerabilities related to it through aliases before
	// searching (see relatedVulnerabilityNames)
	IncludeAliases bool
}

// recordSet is which kinds of package records a search fetches
type recordSet int

const (
	// affectedRecords only fetches affected records, the default
	affectedRecords recordSet = iota
	// allRecords fetches affected records, then unaffected records
	allRecords
	// unaffectedRecords only fetches unaffected records, used when nothing but the not-affected state is asked for
	unaffectedRecords
)

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

// decorate adds the KEV and EPSS decorations to every record, looking up each distinct set of CVEs once
func (r *packageRecords) decorate(reader v6.VulnerabilityDecoratorStoreReader) {
	// decorations only depend on the CVEs of the record, so that is the cache key
	byCVEs := make(map[string]vulnerabilityDecorations)
	decorations := func(cv canonicalVulnerability, current *vulnerabilityDecorations) {
		key := strings.Join(cv.getCVEs(), ",")
		if d, ok := byCVEs[key]; ok {
			*current = d
			return
		}
		decorateVulnerabilities(reader, cv)
		byCVEs[key] = *current
	}

	for _, pkgs := range [][]affectedPackageWithDecorations{r.affectedPkgs, r.unaffectedPkgs} {
		for i := range pkgs {
			decorations(&pkgs[i], &pkgs[i].vulnerabilityDecorations)
		}
	}
	for _, cpes := range [][]affectedCPEWithDecorations{r.affectedCPEs, r.unaffectedCPEs} {
		for i := range cpes {
			decorations(&cpes[i], &cpes[i].vulnerabilityDecorations)
		}
	}
}

// keepUnaffectedForAffectedVulnerabilities drops unaffected records for vulnerabilities without any affected records
func (r *packageRecords) keepUnaffectedForAffectedVulnerabilities() {
	// grouped the same way as matches, by the preloaded vulnerability
	affected := make(map[v6.ID]bool)
	for _, p := range r.affectedPkgs {
		if p.Vulnerability != nil {
			affected[p.Vulnerability.ID] = true
		}
	}
	for _, c := range r.affectedCPEs {
		if c.Vulnerability != nil {
			affected[c.Vulnerability.ID] = true
		}
	}

	r.unaffectedPkgs = slices.DeleteFunc(r.unaffectedPkgs, func(p affectedPackageWithDecorations) bool {
		return p.Vulnerability == nil || !affected[p.Vulnerability.ID]
	})
	r.unaffectedCPEs = slices.DeleteFunc(r.unaffectedCPEs, func(c affectedCPEWithDecorations) bool {
		return c.Vulnerability == nil || !affected[c.Vulnerability.ID]
	})
}

// findAffectedPackages fetches the records in the given set, without decorations. Callers decorate once they have
// filtered the records, so records that are dropped are never decorated.
func findAffectedPackages(reader interface {
	v6.AffectedPackageStoreReader
	v6.AffectedCPEStoreReader
	v6.UnaffectedPackageStoreReader
	v6.UnaffectedCPEStoreReader
}, config AffectedPackagesOptions, set recordSet,
) (packageRecords, error) {
	pkgSpecs := config.Package
	cpeSpecs := config.CPE

	if config.RecordLimit == 0 {
		log.Warn("no record limit set! For queries with large result sets this may result in performance issues")
	}

	if len(config.Vulnerability) == 0 && len(pkgSpecs) == 0 && len(cpeSpecs) == 0 {
		return packageRecords{}, ErrNoSearchCriteria
	}

	// don't allow for searching by any package AND any CPE AND any vulnerability AND any OS. Since these searches
	// are oriented by primarily package, we only want to have ANY package/CPE when there is a vulnerability or OS specified.
	if len(config.Vulnerability) > 0 || !config.OS.IsAny() {
		if len(pkgSpecs) == 0 {
			pkgSpecs = []*v6.PackageSpecifier{v6.AnyPackageSpecified}
		}

		if len(cpeSpecs) == 0 {
			cpeSpecs = []*v6.PackageSpecifier{v6.AnyPackageSpecified}
		}
	}

	// the records found before the limit was reached are returned with the limit error, any other error drops them
	partial := func(records packageRecords, err error) (packageRecords, error) {
		if errors.Is(err, v6.ErrLimitReached) {
			return records, err
		}
		return packageRecords{}, err
	}

	var records packageRecords
	var err error
	if set != unaffectedRecords {
		records.affectedPkgs, records.affectedCPEs, err = findRecords(affectedGetters(reader), config, pkgSpecs, cpeSpecs)
		if err != nil {
			// unaffected records come after affected records, so they are skipped once the limit is reached
			return partial(records, err)
		}
	}

	if set != affectedRecords {
		records.unaffectedPkgs, records.unaffectedCPEs, err = findRecords(unaffectedGetters(reader), config, pkgSpecs, cpeSpecs)
		if err != nil {
			return partial(records, err)
		}
	}

	return records, nil
}

// recordGetters fetch one kind of package and CPE record, returned as the affected handle types
type recordGetters struct {
	// kind is "affected" or "unaffected", used in logs and errors
	kind string
	pkgs func(*v6.PackageSpecifier, *v6.GetPackageOptions) ([]v6.AffectedPackageHandle, error)
	cpes func(*cpe.Attributes, *v6.GetCPEOptions) ([]v6.AffectedCPEHandle, error)
}

func affectedGetters(reader interface {
	v6.AffectedPackageStoreReader
	v6.AffectedCPEStoreReader
}) recordGetters {
	return recordGetters{kind: "affected", pkgs: reader.GetAffectedPackages, cpes: reader.GetAffectedCPEs}
}

// unaffectedGetters converts unaffected handles to the affected handle types, which share the same underlying types
func unaffectedGetters(reader interface {
	v6.UnaffectedPackageStoreReader
	v6.UnaffectedCPEStoreReader
}) recordGetters {
	return recordGetters{
		kind: "unaffected",
		pkgs: func(pkg *v6.PackageSpecifier, opts *v6.GetPackageOptions) ([]v6.AffectedPackageHandle, error) {
			found, err := reader.GetUnaffectedPackages(pkg, opts)
			converted := make([]v6.AffectedPackageHandle, len(found))
			for i := range found {
				converted[i] = v6.AffectedPackageHandle(found[i])
			}
			return converted, err
		},
		cpes: func(c *cpe.Attributes, opts *v6.GetCPEOptions) ([]v6.AffectedCPEHandle, error) {
			found, err := reader.GetUnaffectedCPEs(c, opts)
			converted := make([]v6.AffectedCPEHandle, len(found))
			for i := range found {
				converted[i] = v6.AffectedCPEHandle(found[i])
			}
			return converted, err
		},
	}
}

// findRecords fetches one kind of package and CPE record. Each query gets the full record limit, like every other
// db search query. The records found before an error are returned along with it.
func findRecords(get recordGetters, config AffectedPackagesOptions, pkgSpecs, cpeSpecs v6.PackageSpecifiers) ([]affectedPackageWithDecorations, []affectedCPEWithDecorations, error) {
	var pkgs []affectedPackageWithDecorations
	var cpes []affectedCPEWithDecorations

	for _, pkgSpec := range pkgSpecs {
		log.WithFields("vulns", len(config.Vulnerability), "pkg", pkgSpec, "os", config.OS).Debugf("searching for %s packages", get.kind)

		found, err := get.pkgs(pkgSpec, &v6.GetPackageOptions{
			PreloadOS:             true,
			PreloadPackage:        true,
			PreloadPackageCPEs:    false,
			PreloadVulnerability:  true,
			PreloadBlob:           true,
			OSs:                   config.OS,
			Vulnerabilities:       config.Vulnerability,
			AllowBroadCPEMatching: config.AllowBroadCPEMatching,
			Limit:                 config.RecordLimit,
		})

		for i := range found {
			pkgs = append(pkgs, affectedPackageWithDecorations{AffectedPackageHandle: found[i]})
		}

		if err != nil {
			if errors.Is(err, v6.ErrLimitReached) {
				return pkgs, cpes, err
			}
			return pkgs, cpes, fmt.Errorf("unable to get %s packages: %w", get.kind, err)
		}
	}

	// CPE records have no OS, so they can't match an OS filter
	if !config.OS.IsAny() {
		return pkgs, cpes, nil
	}

	for _, cpeSpec := range cpeSpecs {
		var searchCPE *cpe.Attributes
		if cpeSpec != nil {
			searchCPE = cpeSpec.CPE
		}

		log.WithFields("vulns", len(config.Vulnerability), "cpe", cpeSpec).Debugf("searching for %s cpes", get.kind)

		found, err := get.cpes(searchCPE, &v6.GetCPEOptions{
			PreloadCPE:            true,
			PreloadVulnerability:  true,
			PreloadBlob:           true,
			Vulnerabilities:       config.Vulnerability,
			AllowBroadCPEMatching: config.AllowBroadCPEMatching,
			Limit:                 config.RecordLimit,
		})

		for i := range found {
			cpes = append(cpes, affectedCPEWithDecorations{AffectedCPEHandle: found[i]})
		}

		if err != nil {
			if errors.Is(err, v6.ErrLimitReached) {
				return pkgs, cpes, err
			}
			return pkgs, cpes, fmt.Errorf("unable to get %s cpes: %w", get.kind, err)
		}
	}

	return pkgs, cpes, nil
}
