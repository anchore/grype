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

var _ clio.PostLoader = (*search)(nil)

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

func (cfg search) GetScope() source.Scope {
	return source.ParseScope(cfg.Scope)
}
