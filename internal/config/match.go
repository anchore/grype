package config

import (
	"github.com/spf13/viper"
)

// matchConfig contains all matching-related configuration options available to the user via the application config.
type matchConfig struct {
	Java       matcherConfig `yaml:"java" json:"java" mapstructure:"java"`                   // settings for the java matcher
	Dotnet     matcherConfig `yaml:"dotnet" json:"dotnet" mapstructure:"dotnet"`             // settings for the dotnet matcher
	Golang     matcherConfig `yaml:"golang" json:"golang" mapstructure:"golang"`             // settings for the golang matcher
	Javascript matcherConfig `yaml:"javascript" json:"javascript" mapstructure:"javascript"` // settings for the javascript matcher
	Python     matcherConfig `yaml:"python" json:"python" mapstructure:"python"`             // settings for the python matcher
	Ruby       matcherConfig `yaml:"ruby" json:"ruby" mapstructure:"ruby"`                   // settings for the ruby matcher
	Stock      matcherConfig `yaml:"stock" json:"stock" mapstructure:"stock"`                // settings for the default/stock matcher
}

type matcherConfig struct {
	UseCPEs bool `yaml:"using-cpes" json:"using-cpes" mapstructure:"using-cpes"` // if CPEs should be used during matching
}

func (cfg matchConfig) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("match.java.using-cpes", true)
	v.SetDefault("match.dotnet.using-cpes", true)
	v.SetDefault("match.golang.using-cpes", true)
	v.SetDefault("match.javascript.using-cpes", false)
	v.SetDefault("match.python.using-cpes", true)
	v.SetDefault("match.ruby.using-cpes", true)
	v.SetDefault("match.stock.using-cpes", true)
}
