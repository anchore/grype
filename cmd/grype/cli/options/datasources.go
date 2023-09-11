package options

import (
	"github.com/anchore/grype/grype/matcher/java"
)

const (
	defaultMavenBaseURL = "https://search.maven.org/solrsearch/select"
)

type externalSources struct {
	Enable bool  `yaml:"enable" json:"enable" mapstructure:"enable"`
	Maven  maven `yaml:"maven" json:"maven" mapstructure:"maven"`
}

type maven struct {
	SearchUpstreamBySha1 bool   `yaml:"search-upstream" json:"searchUpstreamBySha1" mapstructure:"search-maven-upstream"`
	BaseURL              string `yaml:"base-url" json:"baseUrl" mapstructure:"base-url"`
}

func defaultExternalSources() externalSources {
	return externalSources{
		Maven: maven{
			SearchUpstreamBySha1: true,
			BaseURL:              defaultMavenBaseURL,
		},
	}
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
