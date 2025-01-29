package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/source"
)

type search struct {
	Scope                    string `yaml:"scope" json:"scope" mapstructure:"scope"`
	IncludeUnindexedArchives bool   `yaml:"unindexed-archives" json:"unindexed-archives" mapstructure:"unindexed-archives"`
	IncludeIndexedArchives   bool   `yaml:"indexed-archives" json:"indexed-archives" mapstructure:"indexed-archives"`
}

var _ interface {
	clio.PostLoader
	clio.FieldDescriber
} = (*search)(nil)

func defaultSearch(scope source.Scope) search {
	c := cataloging.DefaultArchiveSearchConfig()
	return search{
		Scope:                    scope.String(),
		IncludeUnindexedArchives: c.IncludeUnindexedArchives,
		IncludeIndexedArchives:   c.IncludeIndexedArchives,
	}
}

func (cfg *search) PostLoad() error {
	scopeOption := cfg.GetScope()
	if scopeOption == source.UnknownScope {
		return fmt.Errorf("bad scope value %q", cfg.Scope)
	}
	return nil
}

func (cfg *search) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&cfg.IncludeIndexedArchives, `search within archives that do contain a file index to search against (zip)
note: for now this only applies to the java package cataloger`)
	descriptions.Add(&cfg.IncludeUnindexedArchives, `search within archives that do not contain a file index to search against (tar, tar.gz, tar.bz2, etc)
note: enabling this may result in a performance impact since all discovered compressed tars will be decompressed
note: for now this only applies to the java package cataloger`)
}

func (cfg search) GetScope() source.Scope {
	return source.ParseScope(cfg.Scope)
}
