package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/version"
)

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
	Rpm        rpmConfig     `yaml:"rpm" json:"rpm" mapstructure:"rpm"`                      // settings for the rpm matcher
	Dpkg       dpkgConfig    `yaml:"dpkg" json:"dpkg" mapstructure:"dpkg"`                   // settings for the dpkg matcher
}

var _ interface {
	clio.FieldDescriber
	clio.PostLoader
} = (*matchConfig)(nil)

type matcherConfig struct {
	UseCPEs bool `yaml:"using-cpes" json:"using-cpes" mapstructure:"using-cpes"` // if CPEs should be used during matching
}

type golangConfig struct {
	matcherConfig                          `yaml:",inline" mapstructure:",squash"`
	AlwaysUseCPEForStdlib                  bool `yaml:"always-use-cpe-for-stdlib" json:"always-use-cpe-for-stdlib" mapstructure:"always-use-cpe-for-stdlib"`                                                       // if CPEs should be used during matching
	AllowMainModulePseudoVersionComparison bool `yaml:"allow-main-module-pseudo-version-comparison" json:"allow-main-module-pseudo-version-comparison" mapstructure:"allow-main-module-pseudo-version-comparison"` // if pseudo versions should be compared
}

// rpmConfig contains configuration for the RPM matcher.
type rpmConfig struct {
	matcherConfig `yaml:",inline" mapstructure:",squash"`
	// MissingEpochStrategy controls how missing epochs in package versions are handled
	// during vulnerability matching.
	//
	// Valid values:
	//   - "zero" (default): Treat missing epochs as 0
	//   - "auto": Assume missing epoch matches the constraint's epoch
	//
	// The "zero" strategy follows RPM specification guidance and maintains backward
	// compatibility with existing Grype behavior. The "auto" strategy reduces false
	// positives by recognizing that distros rarely track multiple epochs of the same
	// package in the same release.
	//
	// Example:
	//   Package version: 2.0.0 (no epoch)
	//   Constraint: < 1:1.5.0 (epoch 1)
	//
	//   With "zero": Treat package as 0:2.0.0 → MATCH (0 < 1)
	//   With "auto": Treat package as 1:2.0.0 → NO MATCH (2.0.0 > 1.5.0)
	MissingEpochStrategy string `yaml:"missing-epoch-strategy" json:"missing-epoch-strategy" mapstructure:"missing-epoch-strategy"`
}

// dpkgConfig contains configuration for the dpkg matcher.
type dpkgConfig struct {
	matcherConfig `yaml:",inline" mapstructure:",squash"`
	// MissingEpochStrategy controls how missing epochs in package versions are handled
	// during vulnerability matching.
	//
	// Valid values:
	//   - "zero" (default): Treat missing epochs as 0
	//   - "auto": Assume missing epoch matches the constraint's epoch
	//
	// The "zero" strategy follows dpkg specification guidance and maintains backward
	// compatibility with existing Grype behavior. The "auto" strategy reduces false
	// positives by recognizing that distros rarely track multiple epochs of the same
	// package in the same release.
	//
	// Example:
	//   Package version: 2.0.0 (no epoch)
	//   Constraint: < 1:1.5.0 (epoch 1)
	//
	//   With "zero": Treat package as 0:2.0.0 → MATCH (0 < 1)
	//   With "auto": Treat package as 1:2.0.0 → NO MATCH (2.0.0 > 1.5.0)
	MissingEpochStrategy string `yaml:"missing-epoch-strategy" json:"missing-epoch-strategy" mapstructure:"missing-epoch-strategy"`
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

func defaultRpmConfig() rpmConfig {
	return rpmConfig{
		matcherConfig:        matcherConfig{UseCPEs: true},
		MissingEpochStrategy: version.MissingEpochStrategyZero,
	}
}

func defaultDpkgConfig() dpkgConfig {
	return dpkgConfig{
		matcherConfig:        matcherConfig{UseCPEs: true},
		MissingEpochStrategy: version.MissingEpochStrategyZero,
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
		Rpm:        defaultRpmConfig(),
		Dpkg:       defaultDpkgConfig(),
	}
}

func (cfg *matchConfig) PostLoad() error {
	if err := cfg.Rpm.PostLoad(); err != nil {
		return err
	}
	if err := cfg.Dpkg.PostLoad(); err != nil {
		return err
	}
	return nil
}

// PostLoad validates the RPM configuration.
func (cfg *rpmConfig) PostLoad() error {
	if cfg.MissingEpochStrategy != version.MissingEpochStrategyZero && cfg.MissingEpochStrategy != version.MissingEpochStrategyAuto {
		return fmt.Errorf("invalid rpm.missing-epoch-strategy: %q (allowable: %s, %s)",
			cfg.MissingEpochStrategy, version.MissingEpochStrategyZero, version.MissingEpochStrategyAuto)
	}
	return nil
}

// PostLoad validates the dpkg configuration.
func (cfg *dpkgConfig) PostLoad() error {
	if cfg.MissingEpochStrategy != version.MissingEpochStrategyZero && cfg.MissingEpochStrategy != version.MissingEpochStrategyAuto {
		return fmt.Errorf("invalid dpkg.missing-epoch-strategy: %q (allowable: %s, %s)",
			cfg.MissingEpochStrategy, version.MissingEpochStrategyZero, version.MissingEpochStrategyAuto)
	}
	return nil
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
	descriptions.Add(&cfg.Rpm.MissingEpochStrategy,
		`strategy for handling missing epochs in RPM package versions during matching (options: zero, auto)`)
	descriptions.Add(&cfg.Dpkg.MissingEpochStrategy,
		`strategy for handling missing epochs in dpkg package versions during matching (options: zero, auto)`)
}
