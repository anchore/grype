package version

import (
	"fmt"
	"regexp"
	"strings"
)

var _ Constraint = (*golangConstraint)(nil)

type golangConstraint struct {
	raw        string
	expression constraintExpression
}

func newGolangConstraint(raw string) (golangConstraint, error) {
	constraints, err := newConstraintExpression(raw, newGolangComparator)
	if err != nil {
		return golangConstraint{}, err
	}
	return golangConstraint{
		expression: constraints,
		raw:        raw,
	}, nil
}

func (g golangConstraint) String() string {
	if g.raw == "" {
		return "none (go)"
	}
	return fmt.Sprintf("%s (go)", g.raw)
}

func (g golangConstraint) Satisfied(version *Version) (bool, error) {
	if g.raw == "" {
		return true, nil // the empty constraint is always satisfied
	}

	var constraintContainsPseudoVersion bool
	for _, units := range g.expression.units {
		for _, unit := range units {
			if isPseudoVersion(unit.version) {
				constraintContainsPseudoVersion = true
				break
			}
		}
	}
	// when we get a pseudo version from a package, and the constraint being compared against is not a pseudo version,
	// we should not consider it as satisfied
	// ex: constraint of type ">=v1.0.0", should not be compared to version = "v0.0.0-0.20210101000000-abcdef123456"
	if isPseudoVersion(version.String()) && !constraintContainsPseudoVersion {
		return false, nil
	}

	return g.expression.satisfied(version)
}

// PseudoVersionPattern is a regular expression pattern to match pseudo versions
const pseudoVersionPattern = `^v0\.0\.0[-+].*$`

var pseudoVersionRegex = regexp.MustCompile(pseudoVersionPattern)

// Check if a version string is a pseudo version
func isPseudoVersion(version string) bool {
	// List of prefixes commonly used for pseudo versions
	return pseudoVersionRegex.MatchString(strings.TrimSpace(version))
}

func newGolangComparator(unit constraintUnit) (Comparator, error) {
	ver, err := newGolangVersion(unit.version)
	if err != nil {
		return nil, fmt.Errorf("unable to parse constraint version (%s): %w", unit.version, err)
	}
	return ver, nil
}
