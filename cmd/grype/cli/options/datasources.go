package options

import (
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/matcher/java"
)

const (
	defaultMavenBaseURL = "https://search.maven.org/solrsearch/select"
	defaultAbortAfter   = "10m"
)

type externalSources struct {
	Enable     bool   `yaml:"enable" json:"enable" mapstructure:"enable"`
	AbortAfter string `yaml:"abort-after" json:"abortAfter" mapstructure:"abort-after"`
	Maven      maven  `yaml:"maven" json:"maven" mapstructure:"maven"`
}

var _ interface {
	clio.FieldDescriber
} = (*externalSources)(nil)

type maven struct {
	SearchUpstreamBySha1 bool    `yaml:"search-upstream" json:"searchUpstreamBySha1" mapstructure:"search-maven-upstream"`
	BaseURL              string  `yaml:"base-url" json:"baseUrl" mapstructure:"base-url"`
	AbortAfter           *string `yaml:"abort-after" json:"abortAfter" mapstructure:"abort-after"`
	RateLimit            time.Duration `yaml:"rate-limit" json:"rateLimit" mapstructure:"rate-limit"`
}

func defaultExternalSources() externalSources {
	return externalSources{
		AbortAfter: defaultAbortAfter,
		Maven: maven{
			SearchUpstreamBySha1: true,
			BaseURL:              defaultMavenBaseURL,
			RateLimit:            300 * time.Millisecond,
		},
	}
}

func (cfg externalSources) ToJavaMatcherConfig() java.ExternalSearchConfig {
	// always respect if global config is disabled
	smu := cfg.Maven.SearchUpstreamBySha1
	if !cfg.Enable {
		smu = cfg.Enable
	}

	abortAfter := cfg.AbortAfter
	if cfg.Maven.AbortAfter != nil {
		abortAfter = *cfg.Maven.AbortAfter
	}

	return java.ExternalSearchConfig{
		SearchMavenUpstream: smu,
		MavenBaseURL:        cfg.Maven.BaseURL,
		AbortAfter:          abortAfter,
		MavenRateLimit:      cfg.Maven.RateLimit,
	}
}

func (cfg *externalSources) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&cfg.Enable, `enable Grype searching network source for additional information`)
	descriptions.Add(&cfg.Maven.SearchUpstreamBySha1, `search for Maven artifacts by SHA1`)
	descriptions.Add(&cfg.Maven.BaseURL, `base URL of the Maven repository to search`)
}
