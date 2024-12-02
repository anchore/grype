package options

import (
	"github.com/anchore/clio"
)

// Experimental options are opt-in features that are...
// ...not stable
// ...not yet fully supported
// ...not necessarily tested
// ...not ready for production use
// these may go away at any moment, do not depend on them
type Experimental struct {
	DBv6 bool `yaml:"dbv6" json:"dbv6" mapstructure:"dbv6"`
}

var _ interface {
	clio.FieldDescriber
} = (*Experimental)(nil)

func (cfg *Experimental) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&cfg.DBv6, `use the v6 database schema`)
}
