package options

import "github.com/anchore/clio"

// matchConfig contains all matching-related configuration options available to the user via the application config.
type matchConfig struct {
	Java       matcherConfig `yaml:"java" json:"java" mapstructure:"java"`                   // settings for the java matcher
	JVM        matcherConfig `yaml:"jvm" json:"jvm" mapstructure:"jvm"`                      // settings for the jvm matcher
	Dotnet     matcherConfig `yaml:"dotnet" json:"dotnet" mapstructure:"dotnet"`             // settings for the dotnet matcher
	Golang     golangConfig  `yaml:"golang" json:"golang" mapstructure:"golang"`             // settings for the golang matcher
	Javascript matcherConfig `yaml:"javascript" json:"javascript" mapstructure:"javascript"` // settings for the javascript matcher
	Python     matcherConfig `yaml:"python" json:"python" mapstructure:"python"`             // settings for the python matcher
	Ruby       matcherConfig `yaml:"ruby" json:"ruby" mapstructure:"ruby"`                   // settings for the ruby matcher
	Rust       matcherConfig `yaml:"rust" json:"rust" mapstructure:"rust"`                   // settings for the rust matcher
	Stock      matcherConfig `yaml:"stock" json:"stock" mapstructure:"stock"`                // settings for the default/stock matcher
}

var _ interface {
	clio.FieldDescriber
} = (*matchConfig)(nil)

type matcherConfig struct {
	UseCPEs bool `yaml:"using-cpes" json:"using-cpes" mapstructure:"using-cpes"` // if CPEs should be used during matching
}

type golangConfig struct {
	matcherConfig                          `yaml:",inline" mapstructure:",squash"`
	AlwaysUseCPEForStdlib                  bool `yaml:"always-use-cpe-for-stdlib" json:"always-use-cpe-for-stdlib" mapstructure:"always-use-cpe-for-stdlib"`                                                       // if CPEs should be used during matching
	AllowMainModulePseudoVersionComparison bool `yaml:"allow-main-module-pseudo-version-comparison" json:"allow-main-module-pseudo-version-comparison" mapstructure:"allow-main-module-pseudo-version-comparison"` // if pseudo versions should be compared
}

func defaultGolangConfig() golangConfig {
	return golangConfig{
		matcherConfig: matcherConfig{
			UseCPEs: false,
		},
		AlwaysUseCPEForStdlib:                  true,
		AllowMainModulePseudoVersionComparison: false,
	}
}

func defaultMatchConfig() matchConfig {
	useCpe := matcherConfig{UseCPEs: true}
	dontUseCpe := matcherConfig{UseCPEs: false}
	return matchConfig{
		Java:       dontUseCpe,
		JVM:        useCpe,
		Dotnet:     dontUseCpe,
		Golang:     defaultGolangConfig(),
		Javascript: dontUseCpe,
		Python:     dontUseCpe,
		Ruby:       dontUseCpe,
		Rust:       dontUseCpe,
		Stock:      useCpe,
	}
}

func (cfg *matchConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	usingCpeDescription := `use CPE matching to find vulnerabilities`
	descriptions.Add(&cfg.Java.UseCPEs, usingCpeDescription)
	descriptions.Add(&cfg.Dotnet.UseCPEs, usingCpeDescription)
	descriptions.Add(&cfg.Golang.UseCPEs, usingCpeDescription)
	descriptions.Add(&cfg.Golang.AlwaysUseCPEForStdlib, usingCpeDescription+" for the Go standard library")
	descriptions.Add(&cfg.Golang.AllowMainModulePseudoVersionComparison, `allow comparison between main module pseudo-versions (e.g. v0.0.0-20240413-2b432cf643...)`)
	descriptions.Add(&cfg.Javascript.UseCPEs, usingCpeDescription)
	descriptions.Add(&cfg.Python.UseCPEs, usingCpeDescription)
	descriptions.Add(&cfg.Ruby.UseCPEs, usingCpeDescription)
	descriptions.Add(&cfg.Rust.UseCPEs, usingCpeDescription)
	descriptions.Add(&cfg.Stock.UseCPEs, usingCpeDescription)
}
