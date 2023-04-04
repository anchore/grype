package config

import (
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"

	"github.com/adrg/xdg"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
)

var ErrApplicationConfigNotFound = fmt.Errorf("application config not found")

type defaultValueLoader interface {
	loadDefaultValues(*viper.Viper)
}

type parser interface {
	parseConfigValues() error
}

type Application struct {
	ConfigPath             string                  `yaml:",omitempty" json:"configPath"` // the location where the application config was read from (either from -c or discovered while loading)
	Verbosity              uint                    `yaml:"verbosity,omitempty" json:"verbosity" mapstructure:"verbosity"`
	Output                 string                  `yaml:"output" json:"output" mapstructure:"output"`                                           // -o, the Presenter hint string to use for report formatting
	File                   string                  `yaml:"file" json:"file" mapstructure:"file"`                                                 // --file, the file to write report output to
	Distro                 string                  `yaml:"distro" json:"distro" mapstructure:"distro"`                                           // --distro, specify a distro to explicitly use
	GenerateMissingCPEs    bool                    `yaml:"add-cpes-if-none" json:"add-cpes-if-none" mapstructure:"add-cpes-if-none"`             // --add-cpes-if-none, automatically generate CPEs if they are not present in import (e.g. from a 3rd party SPDX document)
	OutputTemplateFile     string                  `yaml:"output-template-file" json:"output-template-file" mapstructure:"output-template-file"` // -t, the template file to use for formatting the final report
	Quiet                  bool                    `yaml:"quiet" json:"quiet" mapstructure:"quiet"`                                              // -q, indicates to not show any status output to stderr (ETUI or logging UI)
	CheckForAppUpdate      bool                    `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	OnlyFixed              bool                    `yaml:"only-fixed" json:"only-fixed" mapstructure:"only-fixed"`                               // only fail if detected vulns have a fix
	OnlyNotFixed           bool                    `yaml:"only-notfixed" json:"only-notfixed" mapstructure:"only-notfixed"`                      // only fail if detected vulns don't have a fix
	Platform               string                  `yaml:"platform" json:"platform" mapstructure:"platform"`                                     // --platform, override the target platform for a container image
	CliOptions             CliOnlyOptions          `yaml:"-" json:"-"`
	Search                 search                  `yaml:"search" json:"search" mapstructure:"search"`
	Ignore                 []match.IgnoreRule      `yaml:"ignore" json:"ignore" mapstructure:"ignore"`
	Exclusions             []string                `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
	DB                     database                `yaml:"db" json:"db" mapstructure:"db"`
	ExternalSources        externalSources         `yaml:"external-sources" json:"externalSources" mapstructure:"external-sources"`
	Match                  matchConfig             `yaml:"match" json:"match" mapstructure:"match"`
	Dev                    development             `yaml:"dev" json:"dev" mapstructure:"dev"`
	FailOn                 string                  `yaml:"fail-on-severity" json:"fail-on-severity" mapstructure:"fail-on-severity"`
	FailOnSeverity         *vulnerability.Severity `yaml:"-" json:"-"`
	Registry               registry                `yaml:"registry" json:"registry" mapstructure:"registry"`
	Log                    logging                 `yaml:"log" json:"log" mapstructure:"log"`
	ShowSuppressed         bool                    `yaml:"show-suppressed" json:"show-suppressed" mapstructure:"show-suppressed"`
	ByCVE                  bool                    `yaml:"by-cve" json:"by-cve" mapstructure:"by-cve"` // --by-cve, indicates if the original match vulnerability IDs should be preserved or the CVE should be used instead
	Name                   string                  `yaml:"name" json:"name" mapstructure:"name"`
	DefaultImagePullSource string                  `yaml:"default-image-pull-source" json:"default-image-pull-source" mapstructure:"default-image-pull-source"`
}

func newApplicationConfig(v *viper.Viper, cliOpts CliOnlyOptions) *Application {
	config := &Application{
		CliOptions: cliOpts,
	}
	config.loadDefaultValues(v)

	return config
}

func LoadApplicationConfig(v *viper.Viper, cliOpts CliOnlyOptions) (*Application, error) {
	// the user may not have a config, and this is OK, we can use the default config + default cobra cli values instead
	config := newApplicationConfig(v, cliOpts)

	if err := readConfig(v, cliOpts.ConfigPath); err != nil && !errors.Is(err, ErrApplicationConfigNotFound) {
		return nil, err
	}

	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("unable to parse config: %w", err)
	}
	config.ConfigPath = v.ConfigFileUsed()

	if err := config.parseConfigValues(); err != nil {
		return nil, fmt.Errorf("invalid application config: %w", err)
	}

	return config, nil
}

// init loads the default configuration values into the viper instance (before the config values are read and parsed).
func (cfg Application) loadDefaultValues(v *viper.Viper) {
	// set the default values for primitive fields in this struct
	v.SetDefault("check-for-app-update", true)
	v.SetDefault("default-image-pull-source", "")

	// for each field in the configuration struct, see if the field implements the defaultValueLoader interface and invoke it if it does
	value := reflect.ValueOf(cfg)
	for i := 0; i < value.NumField(); i++ {
		// note: the defaultValueLoader method receiver is NOT a pointer receiver.
		if loadable, ok := value.Field(i).Interface().(defaultValueLoader); ok {
			// the field implements defaultValueLoader, call it
			loadable.loadDefaultValues(v)
		}
	}
}

func (cfg *Application) parseConfigValues() error {
	// parse application config options
	for _, optionFn := range []func() error{
		cfg.parseLogLevelOption,
		cfg.parseFailOnOption,
	} {
		if err := optionFn(); err != nil {
			return err
		}
	}

	// parse nested config options
	// for each field in the configuration struct, see if the field implements the parser interface
	// note: the app config is a pointer, so we need to grab the elements explicitly (to traverse the address)
	value := reflect.ValueOf(cfg).Elem()
	for i := 0; i < value.NumField(); i++ {
		// note: since the interface method of parser is a pointer receiver we need to get the value of the field as a pointer.
		if parsable, ok := value.Field(i).Addr().Interface().(parser); ok {
			// the field implements parser, call it
			if err := parsable.parseConfigValues(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (cfg *Application) parseLogLevelOption() error {
	switch {
	case cfg.Quiet:
		// TODO: this is bad: quiet option trumps all other logging options (such as to a file on disk)
		// we should be able to quiet the console logging and leave file logging alone...
		// ... this will be an enhancement for later
		cfg.Log.Level = logger.DisabledLevel

	case cfg.CliOptions.Verbosity > 0:
		verb := cfg.CliOptions.Verbosity
		cfg.Log.Level = logger.LevelFromVerbosity(verb, logger.WarnLevel, logger.InfoLevel, logger.DebugLevel, logger.TraceLevel)

	case cfg.Log.Level != "":
		var err error
		cfg.Log.Level, err = logger.LevelFromString(string(cfg.Log.Level))
		if err != nil {
			return err
		}

		if logger.IsVerbose(cfg.Log.Level) {
			cfg.Verbosity = 1
		}
	default:
		cfg.Log.Level = logger.WarnLevel
	}

	return nil
}

func (cfg *Application) parseFailOnOption() error {
	if cfg.FailOn != "" {
		failOnSeverity := vulnerability.ParseSeverity(cfg.FailOn)
		if failOnSeverity == vulnerability.UnknownSeverity {
			return fmt.Errorf("bad --fail-on severity value '%s'", cfg.FailOn)
		}
		cfg.FailOnSeverity = &failOnSeverity
	}
	return nil
}

func (cfg Application) String() string {
	// yaml is pretty human friendly (at least when compared to json)
	appCfgStr, err := yaml.Marshal(&cfg)

	if err != nil {
		return err.Error()
	}

	return string(appCfgStr)
}

// readConfig attempts to read the given config path from disk or discover an alternate store location
func readConfig(v *viper.Viper, configPath string) error {
	var err error
	v.AutomaticEnv()
	v.SetEnvPrefix(internal.ApplicationName)
	// allow for nested options to be specified via environment variables
	// e.g. pod.context = APPNAME_POD_CONTEXT
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	// use explicitly the given user config
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("unable to read application config=%q : %w", configPath, err)
		}
		// don't fall through to other options if the config path was explicitly provided
		return nil
	}

	// start searching for valid configs in order...

	// 1. look for .<appname>.yaml (in the current directory)
	v.AddConfigPath(".")
	v.SetConfigName("." + internal.ApplicationName)
	if err = v.ReadInConfig(); err == nil {
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	// 2. look for .<appname>/config.yaml (in the current directory)
	v.AddConfigPath("." + internal.ApplicationName)
	v.SetConfigName("config")
	if err = v.ReadInConfig(); err == nil {
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	// 3. look for ~/.<appname>.yaml
	home, err := homedir.Dir()
	if err == nil {
		v.AddConfigPath(home)
		v.SetConfigName("." + internal.ApplicationName)
		if err = v.ReadInConfig(); err == nil {
			return nil
		} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
		}
	}

	// 4. look for <appname>/config.yaml in xdg locations (starting with xdg home config dir, then moving upwards)
	v.AddConfigPath(path.Join(xdg.ConfigHome, internal.ApplicationName))
	for _, dir := range xdg.ConfigDirs {
		v.AddConfigPath(path.Join(dir, internal.ApplicationName))
	}
	v.SetConfigName("config")
	if err = v.ReadInConfig(); err == nil {
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	return ErrApplicationConfigNotFound
}
