package rpmmodularity

import (
	"fmt"

	"github.com/anchore/grype/grype/pkg/qualifier"
	"github.com/anchore/grype/grype/pkg/qualifier/rpmmodularity"
)

type Qualifier struct {
	Kind   string `json:"kind" mapstructure:"kind"`                         // Kind of qualifier
	Module string `json:"module,omitempty" mapstructure:"module,omitempty"` // Modularity label
}

func (q Qualifier) Parse() qualifier.Qualifier {
	return rpmmodularity.NewRpmModularityQualifier(q.Module)
}

func (q Qualifier) String() string {
	return fmt.Sprintf("kind: %s, module: %s", q.Kind, q.Module)
}
