package qualifier

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
)

type Qualifier interface {
	Satisfied(d *distro.Distro, p pkg.Package) (bool, error)
}
