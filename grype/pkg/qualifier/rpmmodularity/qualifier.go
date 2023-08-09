package rpmmodularity

import (
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

type rpmModularity struct {
	module string
}

func New(module string) qualifier.Qualifier {
	return &rpmModularity{module: module}
}

func (r rpmModularity) Satisfied(_ *distro.Distro, p pkg.Package) (bool, error) {
	if p.Metadata == nil {
		// If unable to determine package modularity, the constraint should be considered satisfied
		return true, nil
	}

	m, ok := p.Metadata.(pkg.RpmMetadata)
	if !ok {
		return false, nil
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
