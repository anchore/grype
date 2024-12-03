package options

import (
	"fmt"

	"github.com/anchore/clio"
)

type DBSearchBounds struct {
	RecordLimit int `yaml:"limit" json:"limit" mapstructure:"limit"`
}

func (o *DBSearchBounds) AddFlags(flags clio.FlagSet) {
	flags.IntVarP(&o.RecordLimit, "limit", "", "limit the number of results returned (supports DB schema v6+ only)")
}

func (o *DBSearchBounds) PostLoad() error {
	if o.RecordLimit < 0 {
		return fmt.Errorf("limit must be a positive integer")
	}

	return nil
}
