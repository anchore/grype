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
	SearchMavenUpstream bool   `yaml:"search-maven-upstream" json:"search_maven_upstream" mapstructure:"search-maven-upstream"`
	BaseURL             string `yaml:"baseURL" json:"base_url" mapstructure:"base-url"`
}

func (cfg externalSources) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("external-sources.enable", false)
	v.SetDefault("external-sources.maven.search-maven-upstream", false)
	v.SetDefault("external-sources.maven.base-url", defaultMavenBaseURL)
}

func (cfg externalSources) ToJavaMatcherConfig() java.MatcherConfig {
	return java.MatcherConfig{
		SearchMavenUpstream: cfg.Maven.SearchMavenUpstream,
		MavenBaseURL:        cfg.Maven.BaseURL,
	}
}
