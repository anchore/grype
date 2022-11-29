package config

import (
	"github.com/spf13/viper"

	"github.com/anchore/grype/grype/matcher/java"
)

const (
	defaultMavenBaseURL = "https://search.maven.org/solrsearch/select"
)

type externalSources struct {
	Enable bool  `yaml:"enable" json:"enable" mapstructure:"enable"`
	Maven  maven `yaml:"maven" json:"maven" mapsructure:"maven"`
}

type maven struct {
	SearchUpstreamBySha1 bool   `yaml:"search-upstream" json:"searchUpstreamBySha1" mapstructure:"search-maven-upstream"`
	BaseURL              string `yaml:"base-url" json:"baseUrl" mapstructure:"base-url"`
}

func (cfg externalSources) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("external-sources.enable", false)
	v.SetDefault("external-sources.maven.search-maven-upstream", true)
	v.SetDefault("external-sources.maven.base-url", defaultMavenBaseURL)
}

func (cfg externalSources) ToJavaMatcherConfig() java.ExternalSearchConfig {
	// always respect if global config is disabled
	smu := cfg.Maven.SearchUpstreamBySha1
	if !cfg.Enable {
		smu = cfg.Enable
	}
	return java.ExternalSearchConfig{
		SearchMavenUpstream: smu,
		MavenBaseURL:        cfg.Maven.BaseURL,
	}
}
