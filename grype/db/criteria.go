package db

import (
	"errors"
	"fmt"

	v5 "github.com/anchore/grype/grype/db/v5"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// ByPackageName returns criteria restricting vulnerabilities to match the package name provided
func ByPackageName(name string) vulnerability.Criteria {
	if SchemaVersion == v5.SchemaVersion {
		return v5.NewPackageNameCriteria(name)
	}
	return v6.NewPackageNameCriteria(name)
}

// ByID returns criteria to search by vulnerability ID, such as CVE-2024-9143
func ByID(id string) vulnerability.Criteria {
	if SchemaVersion == v5.SchemaVersion {
		return v5.NewIDCriteria(id)
	}
	return v6.NewIDCriteria(id)
}

// ByCPE returns criteria which will search based on the provided CPE
func ByCPE(c cpe.CPE) vulnerability.Criteria {
	if SchemaVersion == v5.SchemaVersion {
		return v5.NewCPECriteria(c)
	}
	return v6.NewCPECriteria(c)
}

// ByDistro returns criteria which will search based on the provided Distro
func ByDistro(d distro.Distro) vulnerability.Criteria {
	if SchemaVersion == v5.SchemaVersion {
		return v5.NewDistroCriteria(d)
	}
	return v6.NewDistroCriteria(d)
}

// ByLanguage returns criteria which will search based on the package language
func ByLanguage(l syftPkg.Language) vulnerability.Criteria {
	if SchemaVersion == v5.SchemaVersion {
		return v5.NewPackageLanguageCriteria(l)
	}
	return v6.NewLanguageCriteria(l)
}

// ByConstraint returns criteria which will search based on the exact constraint string, such as "< 0"
func ByConstraint(constraint string) vulnerability.Criteria {
	// v6 constraint is compatible with both v5 and v6
	return v6.NewConstraintCriteria(constraint)
}

type versionCriteria struct {
	version version.Version
}

func NewVersionCriteria(v version.Version) vulnerability.Criteria {
	return &versionCriteria{version: v}
}

func (v *versionCriteria) MatchesConstraint(constraint version.Constraint) bool {
	isPackageVulnerable, err := v.matchesConstraint(constraint)
	if err != nil {
		log.Debug(err)
	}
	return isPackageVulnerable
}

func (v *versionCriteria) matchesConstraint(constraint version.Constraint) (bool, error) {
	isPackageVulnerable, err := constraint.Satisfied(&v.version)
	if err != nil {
		var e *version.NonFatalConstraintError
		if errors.As(err, &e) {
			log.Warn(e)
		} else {
			return false, fmt.Errorf("failed to check constraint=%v version=%v: %w", constraint, v, err)
		}
	}
	return isPackageVulnerable, nil
}

func (v *versionCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, error) {
	return v.matchesConstraint(vuln.Constraint)
}

var _ interface {
	vulnerability.Criteria
} = (*versionCriteria)(nil)

type constraintCriteria struct {
	version version.Version
}

func NewConstraintCriteria(v version.Version) vulnerability.Criteria {
	return &constraintCriteria{version: v}
}

func (v *constraintCriteria) MatchesConstraint(constraint version.Constraint) bool {
	isPackageVulnerable, err := v.matchesConstraint(constraint)
	if err != nil {
		log.Debug(err)
	}
	return isPackageVulnerable
}

func (v *constraintCriteria) matchesConstraint(constraint version.Constraint) (bool, error) {
	isPackageVulnerable, err := constraint.Satisfied(&v.version)
	if err != nil {
		var e *version.NonFatalConstraintError
		if errors.As(err, &e) {
			log.Warn(e)
		} else {
			return false, fmt.Errorf("failed to check constraint=%v version=%v: %w", constraint, v, err)
		}
	}
	return isPackageVulnerable, nil
}

func (v *constraintCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, error) {
	return v.matchesConstraint(vuln.Constraint)
}

var _ interface {
	vulnerability.Criteria
} = (*constraintCriteria)(nil)

// ------- Utilities -------

// funcCriteria implements vulnerability.Criteria by providing a function implementing the same signature as MatchVulnerability
type funcCriteria struct {
	f func(vulnerability.Vulnerability) (bool, error)
}

func (f funcCriteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, error) {
	return f.f(value)
}

var _ vulnerability.Criteria = (*funcCriteria)(nil)

// NewFuncCriteria returns criteria which will use the provided function as inclusion criteria
func NewFuncCriteria(f func(vulnerability.Vulnerability) (bool, error)) vulnerability.Criteria {
	return funcCriteria{f: f}
}

// funcCriteria implements vulnerability.Criteria by providing a function implementing the same signature as MatchVulnerability
type constraintFuncCriteria struct {
	f func(constraint version.Constraint) (bool, error)
}

// versionConstraintMatcher interface in v6
func (f *constraintFuncCriteria) MatchesConstraint(constraint version.Constraint) (bool, error) {
	return f.f(constraint)
}

func (f *constraintFuncCriteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, error) {
	return f.f(value.Constraint)
}

var _ interface {
	vulnerability.Criteria
	// v6.versionConstraintMatcher // TODO should these v6 interfaces be public?
} = (*constraintFuncCriteria)(nil)

// NewConstraintFuncCriteria returns criteria which will use the provided function as inclusion criteria
func NewConstraintFuncCriteria(f func(constraint version.Constraint) (bool, error)) vulnerability.Criteria {
	return &constraintFuncCriteria{f: f}
}

// byMany returns criteria which will search based on the provided single criteria function and multiple values
// func byMany[T any](criteriaFn func(T) vulnerability.Criteria, c ...T) vulnerability.Criteria {
//	return anyOf(reduce(c, nil, func(criteria []vulnerability.Criteria, t T) []vulnerability.Criteria {
//		return append(criteria, criteriaFn(t))
//	})...)
//}

// anyOf returns criteria that matches any of the provided criteria -- think of this as an SQL OR statement between
// func anyOf(c ...vulnerability.Criteria) vulnerability.Criteria {
//	return v6.NewOrCriteria(c...)
//}

// allOf returns a singular criteria that must match _all_ of the provided criteria
// func allOf(c ...vulnerability.Criteria) vulnerability.Criteria {
//	return v6.NewAndCriteria(c...)
//}

// reduce is a simplistic reducer function
// func reduce[Incoming any, Return any](values []Incoming, initial Return, reducer func(Return, Incoming) Return) Return {
//	for _, value := range values {
//		initial = reducer(initial, value)
//	}
//	return initial
//}
