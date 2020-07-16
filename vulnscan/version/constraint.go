package version

import (
	"fmt"
)

type Constraint interface {
	fmt.Stringer
	Satisfied(*Version) (bool, error)
}

func GetConstraint(constStr string, format Format) (Constraint, error) {
	switch format {
	case SemanticFormat:
		return newSemanticConstraint(constStr)
	case DebFormat:
		return newDebConstraint(constStr)
	case RpmFormat:
		return newRpmConstraint(constStr)
	case UnknownFormat:
		return newFuzzyConstraint(constStr)
	}
	return nil, fmt.Errorf("could not find constraint for given format: %s", format)
}

// MustGetConstraint is meant for testing only, do not use within the library
func MustGetConstraint(constStr string, format Format) Constraint {
	constraint, err := GetConstraint(constStr, format)
	if err != nil {
		panic(err)
	}
	return constraint
}
