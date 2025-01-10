package v6

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// errRequirePostFilter should be returned if specifiers require post-filtering
var errRequirePostFilter = fmt.Errorf("require post filtering")

// ------ V6 store-specific Interfaces ------

// queryPackageSpecifier is used for searches which use the PackageSpecifier
type queryPackageSpecifier interface {
	// PackageSpecifier is able to modify the provided specifier during queries.
	// if the error return value is nil, this indicates the modification to the specifier contained
	// all necessary filtering and the specifier may skip MatchesVulnerability calls later, but
	// returning errRequirePostFilter will cause the criteria to be applied to found vulnerabilities
	PackageSpecifier(*PackageSpecifier) error
}

// queryVulnerabilitySpecifier is used for searches which use the VulnerabilitySpecifier
type queryVulnerabilitySpecifier interface {
	// VulnerabilitySpecifier is able to modify the provided specifier during queries.
	// if the error return value is nil, this indicates the modification to the specifier contained
	// all necessary filtering and the specifier may skip MatchesVulnerability calls later
	// returning errRequirePostFilter will cause the criteria to be applied to found vulnerabilities
	VulnerabilitySpecifier(*VulnerabilitySpecifier) error
}

// queryCPESpecifier is used for searches which use cpe.Attributes
type queryCPESpecifier interface {
	// CPESpecifier is able to modify the provided specifier during queries.
	// if the error return value is nil, this indicates the modification to the specifier contained
	// all necessary filtering and the specifier may skip MatchesVulnerability calls later
	// returning errRequirePostFilter will cause the criteria to be applied to found vulnerabilities
	CPESpecifier(*cpe.Attributes) error
}

// queryOSSpecifier is used for searches which use the OSSpecifier
type queryOSSpecifier interface {
	// OSSpecifier is able to modify the provided specifier during queries.
	// if the error return value is nil, this indicates the modification to the specifier contained
	// all necessary filtering and the specifier may skip MatchesVulnerability calls later
	// returning errRequirePostFilter will cause the criteria to be applied to found vulnerabilities
	OSSpecifier(*OSSpecifier) error
}

// constraintMatcher is used for searches which include an exact constraint rather than a version range,
// for example if a user wants to find NAK entries with constraint "< 0"
type constraintMatcher interface {
	MatchesConstraint(string) bool
}

// versionConstraintMatcher is used for searches which include version.Constraints; this should be used instead of
// post-filtering vulnerabilities in order to most efficiently hydrate data in memory
type versionConstraintMatcher interface {
	MatchesConstraint(version.Constraint) (bool, error)
}

// requiredCriteriaContainer is an interface criteria implementations may provide to give access
// to nested criteria, which may be expanded while processing unique criteria sets. for example,
// the "AND" condition implements this to allow FindVulnerabilities to determine nested database constraints
// that may be applied
type requiredCriteriaContainer interface {
	RequiredCriteria() []vulnerability.Criteria
}

// optionalCriteriaContainer is an interface criteria implementations may provide to give access
// to nested criteria, which may be expanded while processing unique criteria sets. for example,
// the "OR" condition implements this to allow FindVulnerabilities to determine nested database constraints
// that may be applied
type optionalCriteriaContainer interface {
	OptionalCriteria() []vulnerability.Criteria
}

// ------- Criteria implementations --------

// packageNameCriteria is a v6-optimized package name matcher
type packageNameCriteria struct {
	packageName string
}

func NewPackageNameCriteria(name string) vulnerability.Criteria {
	return &packageNameCriteria{
		packageName: name,
	}
}

func (v *packageNameCriteria) PackageSpecifier(specifier *PackageSpecifier) error {
	if specifier.Name == "" {
		specifier.Name = v.packageName
		return nil
	}
	return errRequirePostFilter
}

func (v *packageNameCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, error) {
	return vuln.PackageName == v.packageName, nil
}

var _ interface {
	vulnerability.Criteria
	queryPackageSpecifier
} = (*packageNameCriteria)(nil)

// cpeCriteria implements v6-optimized cpe search criteria
type cpeCriteria struct {
	cpe cpe.CPE
}

func NewCPECriteria(c cpe.CPE) vulnerability.Criteria {
	return &cpeCriteria{
		cpe: c,
	}
}

func (v *cpeCriteria) CPESpecifier(c *cpe.Attributes) error {
	if c == nil || c.Product == "" {
		*c = v.cpe.Attributes
		return nil
	}
	return errRequirePostFilter
}

func (v *cpeCriteria) PackageSpecifier(c *PackageSpecifier) error {
	if c.CPE == nil {
		c.CPE = &v.cpe.Attributes
		return nil
	}
	return errRequirePostFilter
}

func (v *cpeCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, error) {
	return containsCPE(vuln.CPEs, v.cpe), nil
}

var _ interface {
	vulnerability.Criteria
	queryCPESpecifier
	queryPackageSpecifier
} = (*cpeCriteria)(nil)

// languageCriteria implements v6-optimized language matching in vulnerabilities
type languageCriteria struct {
	language syftPkg.Language
}

func NewLanguageCriteria(lang syftPkg.Language) vulnerability.Criteria {
	return &languageCriteria{
		language: lang,
	}
}

func (v *languageCriteria) PackageSpecifier(specifier *PackageSpecifier) error {
	specifier.Type = string(v.language)
	return nil
}

func (v *languageCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, error) {
	return vuln.Namespace == string(v.language), nil // FIXME -- where to find language?
}

var _ interface {
	vulnerability.Criteria
	queryPackageSpecifier
} = (*languageCriteria)(nil)

// constraintCriteria implements v6-optimized exact constraint matching, such as when searching for "< 0"
type constraintCriteria struct {
	constraint string
}

func NewConstraintCriteria(constraint string) vulnerability.Criteria {
	return &constraintCriteria{
		constraint: constraint,
	}
}

func (v *constraintCriteria) MatchesConstraint(constraint string) bool {
	// this matches the raw constraint value
	return constraint == v.constraint
}

func (v *constraintCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, error) {
	// TODO improve this; constraint could/should have a Constraint() string / Raw() string method
	return strings.TrimSpace(strings.Split(vuln.Constraint.String(), "(")[0]) == v.constraint, nil
}

var _ interface {
	vulnerability.Criteria
	constraintMatcher
} = (*constraintCriteria)(nil)

type distroCriteria struct {
	distro distro.Distro
}

func NewDistroCriteria(d distro.Distro) vulnerability.Criteria {
	return &distroCriteria{
		distro: d,
	}
}

func (v *distroCriteria) OSSpecifier(c *OSSpecifier) error {
	if c.Name == "" {
		c.Name = v.distro.Name()
		c.MajorVersion = v.distro.MajorVersion()
		c.MinorVersion = v.distro.MinorVersion()
		return nil
	}
	return nil // FIXME: errRequirePostFilter
}

func (v *distroCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, error) {
	return vuln.Namespace != v.distro.String(), nil // FIXME -- where to find distro?
}

var _ interface {
	vulnerability.Criteria
	queryOSSpecifier
} = (*distroCriteria)(nil)

// idCriteria is able to match vulnerabilities to the assigned ID, such as CVE-2024-1000 or GHSA-g2x7-ar59-85z5
type idCriteria struct {
	id string
}

func NewIDCriteria(id string) vulnerability.Criteria {
	return &idCriteria{
		id: id,
	}
}

func (v *idCriteria) VulnerabilitySpecifier(c *VulnerabilitySpecifier) error {
	if c.Name == "" {
		c.Name = v.id
		return nil
	}
	return errRequirePostFilter
}

func (v *idCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, error) {
	return vuln.ID != v.id, nil
}

var _ interface {
	vulnerability.Criteria
	queryVulnerabilitySpecifier
} = (*idCriteria)(nil)

// orCriteria provides a way to specify multiple criteria to be used
type orCriteria struct {
	criteria []vulnerability.Criteria
}

func NewOrCriteria(criteria ...vulnerability.Criteria) vulnerability.Criteria {
	return &orCriteria{
		criteria: criteria,
	}
}

func (c *orCriteria) OptionalCriteria() []vulnerability.Criteria {
	return c.criteria
}

func (c *orCriteria) MatchesVulnerability(v vulnerability.Vulnerability) (bool, error) {
	for _, crit := range c.criteria {
		matches, err := crit.MatchesVulnerability(v)
		if matches || err != nil {
			return matches, err
		}
	}
	return false, nil
}

var _ interface {
	vulnerability.Criteria
	optionalCriteriaContainer
} = (*orCriteria)(nil)

// multiConstraintMatcher is used internally when multiple version constraint matchers are specified
type multiConstraintMatcher struct {
	a, b versionConstraintMatcher
}

func (m *multiConstraintMatcher) MatchesConstraint(constraint version.Constraint) (bool, error) {
	a, err := m.a.MatchesConstraint(constraint)
	if a || err != nil {
		return a, err
	}
	return m.b.MatchesConstraint(constraint)
}

var _ interface {
	versionConstraintMatcher
} = (*multiConstraintMatcher)(nil)

// containsCPE is a function that returns true if the provided slice contains a matching CPE based on:
// vendor and product matching
func containsCPE(cpes []cpe.CPE, cpe cpe.CPE) bool {
	for _, c := range cpes {
		if matchesAttributes(cpe.Attributes, c.Attributes) {
			return true
		}
	}
	return false
}

func matchesAttributes(a1 cpe.Attributes, a2 cpe.Attributes) bool {
	if !matchesAttribute(a1.Product, a2.Product) ||
		!matchesAttribute(a1.Vendor, a2.Vendor) ||
		!matchesAttribute(a1.Part, a2.Part) ||
		!matchesAttribute(a1.Language, a2.Language) ||
		!matchesAttribute(a1.SWEdition, a2.SWEdition) ||
		!matchesAttribute(a1.TargetSW, a2.TargetSW) ||
		!matchesAttribute(a1.TargetHW, a2.TargetHW) ||
		!matchesAttribute(a1.Other, a2.Other) ||
		!matchesAttribute(a1.Edition, a2.Edition) {
		return false
	}
	return true
}

func matchesAttribute(a1, a2 string) bool {
	return a1 == "" || a2 == "" || strings.EqualFold(a1, a2)
}
