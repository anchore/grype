package pkg

import (
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/source"
)

type Context struct {
	Source *source.Metadata
	Distro *distro.Distro
}
