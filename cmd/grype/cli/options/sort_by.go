package options

import (
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/grype/grype/presenter/models"
)

var _ interface {
	fangs.FlagAdder
	fangs.PostLoader
} = (*SortBy)(nil)

type SortBy struct {
	Criteria         string   `yaml:"sort-by" json:"sort-by" mapstructure:"sort-by"`
	AllowableOptions []string `yaml:"-" json:"-" mapstructure:"-"`
}

func defaultSortBy() SortBy {
	var strategies []string
	for _, s := range models.SortStrategies() {
		strategies = append(strategies, strings.ToLower(s.String()))
	}
	return SortBy{
		Criteria:         models.DefaultSortStrategy.String(),
		AllowableOptions: strategies,
	}
}

func (o *SortBy) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Criteria,
		"sort-by", "",
		fmt.Sprintf("sort the match results with the given strategy, options=%v", o.AllowableOptions),
	)
}

func (o *SortBy) PostLoad() error {
	if !strset.New(o.AllowableOptions...).Has(strings.ToLower(o.Criteria)) {
		return fmt.Errorf("invalid sort-by criteria: %q (allowable: %s)", o.Criteria, strings.Join(o.AllowableOptions, ", "))
	}
	return nil
}
