package search

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// VersionConstraintMatcher is used for searches which include version.Constraints; this should be used instead of
// post-filtering vulnerabilities in order to most efficiently hydrate data in memory
type VersionConstraintMatcher interface {
	MatchesConstraint(constraint version.Constraint) (bool, error)
}

// ByConstraintFunc returns criteria which will use the provided function as inclusion criteria
func ByConstraintFunc(constraintFunc func(constraint version.Constraint) (bool, error)) vulnerability.Criteria {
	return &constraintFuncCriteria{fn: constraintFunc}
}

func ByExactConstraint(constraint string) vulnerability.Criteria {
	return ByConstraintFunc(func(c version.Constraint) (bool, error) {
		// TODO improve this; constraint could/should have a Constraint() string / Raw() string method
		return strings.TrimSpace(strings.Split(c.String(), "(")[0]) == constraint, nil
	})
}

// ByVersion returns criteria which constraints vulnerabilities to those with matching version constraints
func ByVersion(v version.Version) vulnerability.Criteria {
	return ByConstraintFunc(func(constraint version.Constraint) (bool, error) {
		satisfied, err := constraint.Satisfied(&v)
		if err != nil {
			var e *version.NonFatalConstraintError
			if errors.As(err, &e) {
				log.Warn(e)
			} else {
				return false, fmt.Errorf("failed to check constraint=%v version=%v: %w", constraint, v, err)
			}
		}
		return satisfied, nil
	})
}

// constraintFuncCriteria implements vulnerability.Criteria by providing a function implementing the same signature as MatchVulnerability
type constraintFuncCriteria struct {
	fn func(constraint version.Constraint) (bool, error)
}

func (f *constraintFuncCriteria) MatchesConstraint(constraint version.Constraint) (bool, error) {
	return f.fn(constraint)
}

func (f *constraintFuncCriteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, error) {
	return f.fn(value.Constraint)
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
