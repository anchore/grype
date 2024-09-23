package version

import "fmt"

func newGolangConstraint(raw string) (Constraint, error) {
	return newGenericConstraint(raw, newGolangComparator, "go")
}

func newGolangComparator(unit constraintUnit) (Comparator, error) {
	ver, err := newGolangVersion(unit.version)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Golang constraint version (%s): %w", unit.version, err)
	}
	return ver, nil
}
