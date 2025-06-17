package version

func newGolangConstraint(raw string) (Constraint, error) {
	return newGenericConstraint(raw, GolangFormat)
}

// func newGolangComparator(unit constraintUnit) (Comparator, error) {
//	ver, err := newGolangVersion(unit.rawVersion)
//	if err != nil {
//		return nil, fmt.Errorf("unable to parse Golang constraint version (%s): %w", unit.rawVersion, err)
//	}
//	return ver, nil
//}
