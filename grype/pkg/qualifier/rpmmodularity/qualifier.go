package rpmmodularity

import (
	"strings"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

type rpmModularity struct {
	module string
}

func NewRpmModularityQualifier(module string) qualifier.Qualifier {
	return &rpmModularity{module: module}
}

func (r rpmModularity) Satisfied(p pkg.Package) (bool, error) {
	if p.MetadataType == pkg.RpmMetadataType {
		// TODO: Does no ModularityLabel match anything or only no module?
		if p.Metadata == nil {
			return r.module == "", nil
		}

		m, ok := p.Metadata.(pkg.RpmMetadata)

		// If the package metadata was the rpm type but casting failed
		// we assume it would have been satisfied to
		// avoid dropping potential matches
		if !ok {
			return true, nil
		}

		// TODO: Does no ModularityLabel match anything or only no module?
		if m.ModularityLabel == "" {
			return r.module == "", nil
		}

		if r.module == "" {
			return false, nil
		}

		return strings.HasPrefix(m.ModularityLabel, r.module), nil
	}

	return false, nil
}
