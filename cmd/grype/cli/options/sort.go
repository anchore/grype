package options

import (
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/presenter/models"
)

type Sort struct {
	Method    string   `yaml:"sort-by" json:"sort-by" mapstructure:"sort-by"`
	Allowable []string `yaml:"-" json:"-" mapstructure:"-"`
}

func defaultSort() Sort {
	return Sort{
		Method: models.SortByPackage.String(),
		Allowable: func() []string {
			var methods []string
			for _, m := range models.SortStrategies() {
				methods = append(methods, m.String())
			}
			return methods
		}(),
	}
}

func (c *Sort) AddFlags(flags clio.FlagSet) {
	available := strings.Join(c.Allowable, ", ")
	flags.StringVarP(&c.Method, "sort-by", "", fmt.Sprintf("method to sort vulnerbility results by (available=[%s])", available))
}

func (c *Sort) PostLoad() error {
	if len(c.Allowable) > 0 {
		if !strset.New(c.Allowable...).Has(c.Method) {
			return fmt.Errorf("invalid sort-by method: %s (expected one of: %s)", c.Method, strings.Join(c.Allowable, ", "))
		}
	}
	return nil
}
