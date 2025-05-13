package version

import "fmt"

func newGemfileConstraint(raw string) (Constraint, error) {
	return newGenericConstraint(raw, newGemfileComparator, "gem")
}

func newGemfileComparator(unit constraintUnit) (Comparator, error) {
	ver, err := newGemVersion(unit.version)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Gemfile constraint version (%s): %w", unit.version, err)
	}
	return ver, nil
}
