package options

// matchConfig contains all matching-related configuration options available to the user via the application config.
type matchConfig struct {
	Java       matcherConfig `yaml:"java" json:"java" mapstructure:"java"`                   // settings for the java matcher
	Dotnet     matcherConfig `yaml:"dotnet" json:"dotnet" mapstructure:"dotnet"`             // settings for the dotnet matcher
	Golang     golangConfig  `yaml:"golang" json:"golang" mapstructure:"golang"`             // settings for the golang matcher
	Javascript matcherConfig `yaml:"javascript" json:"javascript" mapstructure:"javascript"` // settings for the javascript matcher
	Python     matcherConfig `yaml:"python" json:"python" mapstructure:"python"`             // settings for the python matcher
	Ruby       matcherConfig `yaml:"ruby" json:"ruby" mapstructure:"ruby"`                   // settings for the ruby matcher
	Rust       matcherConfig `yaml:"rust" json:"rust" mapstructure:"rust"`                   // settings for the rust matcher
	Stock      matcherConfig `yaml:"stock" json:"stock" mapstructure:"stock"`                // settings for the default/stock matcher
}

type matcherConfig struct {
	UseCPEs bool `yaml:"using-cpes" json:"using-cpes" mapstructure:"using-cpes"` // if CPEs should be used during matching
}

type golangConfig struct {
	matcherConfig         `yaml:",inline" mapstructure:",squash"`
	AlwaysUseCPEForStdlib bool `yaml:"always-use-cpe-for-stdlib" json:"always-use-cpe-for-stdlib" mapstructure:"always-use-cpe-for-stdlib"` // if CPEs should be used during matching
}

func defaultGolangConfig() golangConfig {
	return golangConfig{
		matcherConfig: matcherConfig{
			UseCPEs: false,
		},
		AlwaysUseCPEForStdlib: true,
	}
}

func defaultMatchConfig() matchConfig {
	useCpe := matcherConfig{UseCPEs: true}
	dontUseCpe := matcherConfig{UseCPEs: false}
	return matchConfig{
		Java:       dontUseCpe,
		Dotnet:     dontUseCpe,
		Golang:     defaultGolangConfig(),
		Javascript: dontUseCpe,
		Python:     dontUseCpe,
		Ruby:       dontUseCpe,
		Rust:       dontUseCpe,
		Stock:      useCpe,
	}
}
