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

	if m.ModularityLabel == nil {
		// If the package modularity is empty (null), the constraint should be considered satisfied.
		// this is the case where the package source does not support expressing modularity.
		return true, nil
	}

	if r.module == "" {
		if *m.ModularityLabel == "" {
			// the DB has a modularity label, but it's empty... we also have a modularity label from a package source
			// that supports being able to express modularity, but it's empty. This is a match.
			return true, nil
		}

		// The package source is able to express modularity, and the DB has a package quality that is empty.
		// Since we are doing a prefix match against the modularity label (which is guaranteed to be non-empty),
		// and we are checking for an empty prefix, this will always match, however, semantically this makes no sense.
		// We don't want package modularities of any value to match this qualifier.
		return false, nil
	}

	return strings.HasPrefix(*m.ModularityLabel, r.module), nil
}
