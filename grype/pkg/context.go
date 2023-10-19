package pkg

import (
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/source"
)

type Context struct {
	Source *source.Description
	Distro *linux.Release
}
