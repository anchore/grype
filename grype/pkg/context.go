package pkg

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/syft/syft/source"
)

type Context struct {
	Source *source.Description
	Distro *distro.Distro
}
