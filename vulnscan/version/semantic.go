package version

import (
	"fmt"

	hashiVer "github.com/hashicorp/go-version"
)

func newSemanticVersion(raw string) (*hashiVer.Version, error) {
	return hashiVer.NewVersion(raw)
}

type semanticConstraint struct {
	raw        string
	constraint hashiVer.Constraints
}

func newSemanticConstraint(constStr string) (semanticConstraint, error) {
	constraints, err := hashiVer.NewConstraint(constStr)
	if err != nil {
		return semanticConstraint{}, err
	}
	return semanticConstraint{
		raw:        constStr,
		constraint: constraints,
	}, nil
}

func (c semanticConstraint) supported(format Format) bool {
	return format == SemanticFormat
}

func (c semanticConstraint) Satisfied(version *Version) (bool, error) {
	if !c.supported(version.Format) {
		return false, fmt.Errorf("(semantic) unsupported format: %s", version.Format)
	}

	if version.rich.semVer == nil {
		return false, fmt.Errorf("no rich semantic version given: %+v", version)
	}
	return c.constraint.Check(version.rich.semVer), nil
}

func (c semanticConstraint) String() string {
	return fmt.Sprintf("%s (semantic)", c.raw)
}
