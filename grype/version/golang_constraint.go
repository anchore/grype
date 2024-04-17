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

	// when we get a pseudo version from the package and the constraint is not a pseudo version, we should not consider it as satisfied
	// ex: constraint = ">=v1.0.0", version = "v0.0.0-0.20210101000000-abcdef123456"
	if isPseudoVersion(version.String()) && !isPseudoVersion(g.raw) {
		return false, nil
	}

	return g.expression.satisfied(version)
}

// Define a regular expression pattern to match pseudo versions
const PseudoVersionPattern = `^v0\.0\.0[-+].*$`

// Check if a version string is a pseudo version
func isPseudoVersion(version string) bool {
	// List of prefixes commonly used for pseudo versions
	regex := regexp.MustCompile(PseudoVersionPattern)

	return regex.MatchString(strings.TrimSpace(version))
}

func newGolangComparator(unit constraintUnit) (Comparator, error) {
	ver, err := newGolangVersion(unit.version)
	if err != nil {
		return nil, fmt.Errorf("unable to parse constraint version (%s): %w", unit.version, err)
	}
	return ver, nil
}
