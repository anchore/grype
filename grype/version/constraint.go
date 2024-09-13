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
	case ApkFormat:
		return newApkConstraint(constStr)
	case SemanticFormat, GemFormat:
		return newSemanticConstraint(constStr)
	case DebFormat:
		return newDebConstraint(constStr)
	case GolangFormat:
		return newGolangConstraint(constStr)
	case MavenFormat:
		return newMavenConstraint(constStr)
	case RpmFormat:
		return newRpmConstraint(constStr)
	case PythonFormat:
		return newPep440Constraint(constStr)
	case KBFormat:
		return newKBConstraint(constStr)
	case PortageFormat:
		return newPortageConstraint(constStr)
	case JVMFormat:
		return newJvmConstraint(constStr)
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

// NonFatalConstraintError should be used any time an unexpected but recoverable condition is encountered while
// checking version constraint satisfaction. The error should get returned by any implementer of the Constraint
// interface. If returned by the Satisfied method on the Constraint interface, this error will be caught and
// logged as a warning in the FindMatchesByPackageDistro function in grype/matcher/common/distro_matchers.go
type NonFatalConstraintError struct {
	constraint Constraint
	version    *Version
	message    string
}

func (e NonFatalConstraintError) Error() string {
	return fmt.Sprintf("Matching raw constraint %s against version %s caused a non-fatal error: %s", e.constraint, e.version, e.message)
}
