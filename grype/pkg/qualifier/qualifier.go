package qualifier

import (
	"github.com/anchore/grype/grype/pkg"
)

type Qualifier interface {
	Satisfied(p pkg.Package) (bool, error)
}
