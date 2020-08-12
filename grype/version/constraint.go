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
	case PythonFormat:
		// This is specific to PythonFormat so that it adheres to PEP440 and its odd corner-cases
		// It is significantly odd enough, that the fuzzyConstraint is the best bet to compare versions.
		// Although this will work in most cases, some oddities aren't supported, like:
		// 1.0b2.post345.dev456 which is allowed by the spec. In that case (a dev release of a post release)
		// the comparator will fail. See https://www.python.org/dev/peps/pep-0440
		return newFuzzyConstraint(constStr, "python")
	case UnknownFormat:
		return newFuzzyConstraint(constStr, "unknown")
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
