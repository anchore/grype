package rpmmodularity

import (
	"strings"

	"github.com/nextlinux/griffon/griffon/distro"
	"github.com/nextlinux/griffon/griffon/pkg"
	"github.com/nextlinux/griffon/griffon/pkg/qualifier"
)

type rpmModularity struct {
	module string
}

func New(module string) qualifier.Qualifier {
	return &rpmModularity{module: module}
}

func (r rpmModularity) Satisfied(_ *distro.Distro, p pkg.Package) (bool, error) {
	if p.MetadataType == pkg.RpmMetadataType {
		// If unable to determine package modularity, the constraint should be considered satisfied
		if p.Metadata == nil {
			return true, nil
		}

		m, ok := p.Metadata.(pkg.RpmMetadata)

		// If the package metadata was the rpm type but casting failed
		// we assume it would have been satisfied to
		// avoid dropping potential matches
		if !ok {
			return true, nil
		}

		// If the package modularity is empty (""), the constraint should be considered satisfied
		if m.ModularityLabel == "" {
			return true, nil
		}

		if r.module == "" {
			return false, nil
		}

		return strings.HasPrefix(m.ModularityLabel, r.module), nil
	}

	return false, nil
}
