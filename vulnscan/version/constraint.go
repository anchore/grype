package version

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/os"
)

type Constraint interface {
	fmt.Stringer
	Satisfied(*Version) (bool, error)
}

// TODO: consider prototype pattern for faster creation and better reuse
func GetConstraint(constStr string, format Format) (Constraint, error) {
	switch format {
	case SemanticFormat:
		return newSemanticConstraint(constStr)
	case DpkgFormat:
		return newDpkgConstraint(constStr)
	}
	return nil, fmt.Errorf("could not find constraint for given format: %s", format)
}

func GetConstraintByOS(constStr string, o os.OS) (Constraint, error) {
	var format Format
	switch o.Type {
	case os.DebianOS:
		format = DpkgFormat
	//...
	default:
		format = UnknownFormat
	}

	return GetConstraint(constStr, format)
}
