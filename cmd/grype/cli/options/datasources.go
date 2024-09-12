package options

import (
	"github.com/anchore/clio"
)

const (
	defaultMavenBaseURL = "https://search.maven.org/solrsearch/select"
)

type externalSources struct {
	Enable *bool `yaml:"enable" json:"enable" mapstructure:"enable"`
	Maven  maven `yaml:"maven" json:"maven" mapstructure:"maven"`
}

var _ interface {
	clio.FieldDescriber
} = (*externalSources)(nil)

type maven struct {
	SearchUpstreamBySha1 *bool  `yaml:"search-upstream" json:"searchUpstreamBySha1" mapstructure:"search-maven-upstream"`
	BaseURL              string `yaml:"base-url" json:"baseUrl" mapstructure:"base-url"`
}

func defaultExternalSources() externalSources {
	return externalSources{
		Maven: maven{
			SearchUpstreamBySha1: nil,
			BaseURL:              defaultMavenBaseURL,
		},
	}
}

func (cfg *externalSources) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&cfg.Enable, `enable Grype searching network source for additional information`)
	descriptions.Add(&cfg.Maven.SearchUpstreamBySha1, `search for Maven artifacts by SHA1`)
	descriptions.Add(&cfg.Maven.BaseURL, `base URL of the Maven repository to search`)
}
