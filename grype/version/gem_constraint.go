package version

import "fmt"

func newGemfileConstraint(raw string) (Constraint, error) {
	return newGenericConstraint(raw, newGemfileComparator, "gem")
}

func newGemfileComparator(unit constraintUnit) (Comparator, error) {
	ver, err := newGemVersion(unit.rawVersion)
	if err != nil {
		return nil, fmt.Errorf("unable to parse gemfile constraint version (%s): %w", unit.rawVersion, err)
	}
	return ver, nil
}
