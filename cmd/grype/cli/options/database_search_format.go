package options

import (
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/clio"
)

type DBSearchFormat struct {
	Output    string   `yaml:"output" json:"output" mapstructure:"output"`
	Allowable []string `yaml:"-" json:"-" mapstructure:"-"`
}

func DefaultDBSearchFormat() DBSearchFormat {
	return DBSearchFormat{
		Output:    "table",
		Allowable: []string{"table", "json"},
	}
}

func (c *DBSearchFormat) AddFlags(flags clio.FlagSet) {
	available := strings.Join(c.Allowable, ", ")
	flags.StringVarP(&c.Output, "output", "o", fmt.Sprintf("format to display results (available=[%s])", available))
}

func (c *DBSearchFormat) PostLoad() error {
	if len(c.Allowable) > 0 {
		if !strset.New(c.Allowable...).Has(c.Output) {
			return fmt.Errorf("invalid output format: %s (expected one of: %s)", c.Output, strings.Join(c.Allowable, ", "))
		}
	}
	return nil
}
