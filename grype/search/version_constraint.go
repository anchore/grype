package search

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

var _ interface {
	vulnerability.Criteria
	VersionConstraintMatcher
} = (*VersionCriteria)(nil)

// VersionConstraintMatcher is used for searches which include version.Constraints; this should be used instead of
// post-filtering vulnerabilities in order to most efficiently hydrate data in memory
type VersionConstraintMatcher interface {
	MatchesConstraint(constraint version.Constraint) (bool, error)
}

// ByConstraintFunc returns criteria which will use the provided function as inclusion criteria
func ByConstraintFunc(constraintFunc func(constraint version.Constraint) (bool, error)) vulnerability.Criteria {
	return &constraintFuncCriteria{fn: constraintFunc}
}

type VersionCriteria struct {
	Version version.Version
}

func (v VersionCriteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, string, error) {
	return ByConstraintFunc(v.criteria).MatchesVulnerability(value)
}

func (v VersionCriteria) MatchesConstraint(constraint version.Constraint) (bool, error) {
	return v.criteria(constraint)
}

func (v VersionCriteria) criteria(constraint version.Constraint) (bool, error) {
	// The config is now embedded in the version itself, so just call Satisfied
	satisfied, err := constraint.Satisfied(&v.Version)

	if err != nil {
		var unsupportedError *version.UnsupportedComparisonError
		if errors.As(err, &unsupportedError) {
			// if the format is unsupported, then the constraint is not satisfied, but this should not be conveyed as an error
			log.WithFields("reason", err).Trace("unsatisfied constraint")
			return false, nil
		}

		var e *version.NonFatalConstraintError
		if errors.As(err, &e) {
			log.Warn(e)
		} else {
			return false, fmt.Errorf("failed to check constraint=%v version=%v: %w", constraint, v, err)
		}
	}
	return satisfied, nil
}

// ByFixedVersion returns criteria which constrains vulnerabilities to those that are fixed based on the provided version,
// in other words: vulnerabilities where the fix version is less than v
func ByFixedVersion(v version.Version) vulnerability.Criteria {
	return &funcCriteria{
		func(vuln vulnerability.Vulnerability) (bool, string, error) {
			var err error
			if vuln.Fix.State != vulnerability.FixStateFixed {
				return false, "", nil
			}
			for _, fixVersion := range vuln.Fix.Versions {
				cmp, e := version.New(fixVersion, v.Format).Compare(&v)
				if e != nil {
					err = e
				}
				if cmp <= 0 {
					// fix version is less than or equal to the provided version, so is considered fixed
					return true, fmt.Sprintf("fix version %v is less than %v", v, fixVersion), err
				}
			}
			return false, "", err
		},
	}
}

// ByVersion returns criteria which constrains vulnerabilities to those with matching version constraints
func ByVersion(v version.Version) vulnerability.Criteria {
	return &VersionCriteria{
		Version: v,
	}
}

// constraintFuncCriteria implements vulnerability.Criteria by providing a function implementing the same signature as MatchVulnerability
type constraintFuncCriteria struct {
	fn      func(constraint version.Constraint) (bool, error)
	summary string
}

func (f *constraintFuncCriteria) MatchesConstraint(constraint version.Constraint) (bool, error) {
	return f.fn(constraint)
}

func (f *constraintFuncCriteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, string, error) {
	if value.Constraint == nil {
		// if there is no constraint, then we cannot match against it
		return false, "no version constraint", nil
	}
	matches, err := f.fn(value.Constraint)
	// TODO: should we do something about this?
	return matches, "", err
}

func (f *constraintFuncCriteria) Summarize() string {
	return f.summary
}

var _ interface {
	vulnerability.Criteria
	VersionConstraintMatcher
} = (*constraintFuncCriteria)(nil)

func MultiConstraintMatcher(a, b VersionConstraintMatcher) VersionConstraintMatcher {
	return &multiConstraintMatcher{
		a: a,
		b: b,
	}
}

// multiConstraintMatcher is used internally when multiple version constraint matchers are specified
type multiConstraintMatcher struct {
	a, b VersionConstraintMatcher
}

func (m *multiConstraintMatcher) MatchesConstraint(constraint version.Constraint) (bool, error) {
	a, err := m.a.MatchesConstraint(constraint)
	if a || err != nil {
		return a, err
	}
	return m.b.MatchesConstraint(constraint)
}

var _ interface {
	VersionConstraintMatcher
} = (*multiConstraintMatcher)(nil)
