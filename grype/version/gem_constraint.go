package version

func newGemfileConstraint(raw string) (Constraint, error) {
	return newGenericConstraint(raw, GemFormat)
}
