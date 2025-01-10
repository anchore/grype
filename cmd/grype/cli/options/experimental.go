package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/db"
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
	clio.PostLoader
} = (*Experimental)(nil)

func (cfg *Experimental) PostLoad() error {
	if cfg.DBv6 {
		db.SchemaVersion = 6 // FIXME -- v6.SchemaVersion
	}
	return nil
}

func (cfg *Experimental) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&cfg.DBv6, `use the v6 database schema`)
}
