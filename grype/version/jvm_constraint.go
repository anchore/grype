package version

func newJvmConstraint(raw string) (Constraint, error) {
	return newGenericConstraint(raw, JVMFormat)
}
