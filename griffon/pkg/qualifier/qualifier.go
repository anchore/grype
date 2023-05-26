package qualifier

import (
	"github.com/nextlinux/griffon/griffon/distro"
	"github.com/nextlinux/griffon/griffon/pkg"
)

type Qualifier interface {
	Satisfied(d *distro.Distro, p pkg.Package) (bool, error)
}
