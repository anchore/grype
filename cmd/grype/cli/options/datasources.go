package options

import (
	"github.com/anchore/clio"
	"time"
	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/matcher/java"
)

const (
	defaultMavenBaseURL = "https://search.maven.org/solrsearch/select"
	defaultAbortAfter   = 10 * time.Minute
)

type externalSources struct {
	Enable     bool           `yaml:"enable" json:"enable" mapstructure:"enable"`
	AbortAfter *time.Duration `yaml:"abort-after" json:"abortAfter" mapstructure:"abort-after"`
	Maven      maven          `yaml:"maven" json:"maven" mapstructure:"maven"`
}

var _ interface {
	clio.FieldDescriber
} = (*externalSources)(nil)

type maven struct {
	SearchUpstreamBySha1 bool           `yaml:"search-upstream" json:"searchUpstreamBySha1" mapstructure:"search-maven-upstream"`
	BaseURL              string         `yaml:"base-url" json:"baseUrl" mapstructure:"base-url"`
	AbortAfter           *time.Duration `yaml:"abort-after" json:"abortAfter" mapstructure:"abort-after"`
}

func defaultExternalSources() externalSources {
	return externalSources{
		Maven: maven{
			SearchUpstreamBySha1: true,
			BaseURL:              defaultMavenBaseURL,
		},
	}
}

func (cfg *externalSources) PostLoad() error {
	// always respect if global config is disabled
	if !cfg.Enable {
		cfg.Maven.SearchUpstreamBySha1 = false
	}

	cfg.Maven.AbortAfter = multiLevelOption[time.Duration](defaultAbortAfter, cfg.AbortAfter, cfg.Maven.AbortAfter)

	return nil
}

func (cfg externalSources) ToJavaMatcherConfig() java.ExternalSearchConfig {
	return java.ExternalSearchConfig{
		SearchMavenUpstream: cfg.Maven.SearchUpstreamBySha1,
		MavenBaseURL:        cfg.Maven.BaseURL,
		AbortAfter:          *cfg.Maven.AbortAfter,
	}
}

func multiLevelOption[T any](defaultValue T, option ...*T) *T {
	result := defaultValue
	for _, opt := range option {
		if opt != nil {
			result = *opt
		}
	}
	return &result
}

func (cfg *externalSources) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&cfg.Enable, `enable Grype searching network source for additional information`)
	descriptions.Add(&cfg.Maven.SearchUpstreamBySha1, `search for Maven artifacts by SHA1`)
	descriptions.Add(&cfg.Maven.BaseURL, `base URL of the Maven repository to search`)
}
