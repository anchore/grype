package config

import (
	"fmt"

	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
	"github.com/spf13/viper"
)

type search struct {
	ScopeOpt                 source.Scope `yaml:"-" json:"-"`
	Scope                    string       `yaml:"scope" json:"scope" mapstructure:"scope"`
	IncludeUnindexedArchives bool         `yaml:"unindexed-archives" json:"unindexed-archives" mapstructure:"unindexed-archives"`
	IncludeIndexedArchives   bool         `yaml:"indexed-archives" json:"indexed-archives" mapstructure:"indexed-archives"`
}

func (cfg *search) parseConfigValues() error {
	scopeOption := source.ParseScope(cfg.Scope)
	if scopeOption == source.UnknownScope {
		return fmt.Errorf("bad scope value %q", cfg.Scope)
	}
	cfg.ScopeOpt = scopeOption

	return nil
}

func (cfg search) loadDefaultValues(v *viper.Viper) {
	c := cataloger.DefaultSearchConfig()
	v.SetDefault("search.unindexed-archives", c.IncludeUnindexedArchives)
	v.SetDefault("search.indexed-archives", c.IncludeIndexedArchives)
}

func (cfg search) ToConfig() cataloger.Config {
	return cataloger.Config{
		Search: cataloger.SearchConfig{
			IncludeIndexedArchives:   cfg.IncludeIndexedArchives,
			IncludeUnindexedArchives: cfg.IncludeUnindexedArchives,
			Scope:                    cfg.ScopeOpt,
		},
	}
}
