package config

import (
	"fmt"
	"path"
	"strings"

	"github.com/adrg/xdg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/vulnscan/internal"
	"github.com/anchore/vulnscan/vulnscan/db"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"go.uber.org/zap/zapcore"
)

type CliOnlyOptions struct {
	ConfigPath string
	Verbosity  int
}

type Application struct {
	ConfigPath        string
	ScopeOpt          scope.Option
	Scope             string  `mapstructure:"scope"`
	Quiet             bool    `mapstructure:"quiet"`
	Log               Logging `mapstructure:"log"`
	CliOptions        CliOnlyOptions
	Db                Database    `mapstructure:"db"`
	Dev               Development `mapstructure:"dev"`
	CheckForAppUpdate bool        `mapstructure:"check-for-app-update"`
}

type Logging struct {
	Structured   bool `mapstructure:"structured"`
	LevelOpt     zapcore.Level
	Level        string `mapstructure:"level"`
	FileLocation string `mapstructure:"file"`
}

type Database struct {
	Dir             string `mapstructure:"cache-dir"`
	UpdateURL       string `mapstructure:"update-url"`
	UpdateOnStartup bool   `mapstructure:"update-on-startup"`
}

type Development struct {
	ProfileCPU bool `mapstructure:"profile-cpu"`
}

func (d Database) ToCuratorConfig() db.Config {
	return db.Config{
		DbDir:      d.Dir,
		ListingURL: d.UpdateURL,
	}
}

func setNonCliDefaultValues(v *viper.Viper) {
	v.SetDefault("log.level", "")
	v.SetDefault("log.file", "")
	v.SetDefault("log.structured", false)
	// e.g. ~/.cache/appname/db
	v.SetDefault("db.cache-dir", path.Join(xdg.CacheHome, internal.ApplicationName, "db"))
	// TODO: change me to the production URL before release
	v.SetDefault("db.update-url", "http://localhost:5000/listing.json")
	// TODO: set this to true before release
	v.SetDefault("db.update-on-startup", false)
	v.SetDefault("dev.profile-cpu", false)
	v.SetDefault("check-for-app-update", true)
}

func LoadConfigFromFile(v *viper.Viper, cliOpts *CliOnlyOptions) (*Application, error) {
	// the user may not have a config, and this is OK, we can use the default config + default cobra cli values instead
	setNonCliDefaultValues(v)
	if cliOpts != nil {
		_ = readConfig(v, cliOpts.ConfigPath)
	} else {
		_ = readConfig(v, "")
	}

	config := &Application{
		CliOptions: *cliOpts,
	}
	err := v.Unmarshal(config)
	if err != nil {
		return nil, fmt.Errorf("unable to parse config: %w", err)
	}
	config.ConfigPath = v.ConfigFileUsed()

	err = config.Build()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return config, nil
}

func (cfg *Application) Build() error {
	// set the scope
	scopeOption := scope.ParseOption(cfg.Scope)
	if scopeOption == scope.UnknownScope {
		return fmt.Errorf("bad --scope value '%s'", cfg.Scope)
	}
	cfg.ScopeOpt = scopeOption

	if cfg.Quiet {
		// TODO: this is bad: quiet option trumps all other logging options
		// we should be able to quiet the console logging and leave file logging alone...
		// ... this will be an enhancement for later
		cfg.Log.LevelOpt = zapcore.PanicLevel
	} else {
		if cfg.Log.Level != "" {
			if cfg.CliOptions.Verbosity > 0 {
				return fmt.Errorf("cannot explicitly set log level (cfg file or env var) and use -v flag together")
			}

			// set the log level explicitly
			err := cfg.Log.LevelOpt.Set(cfg.Log.Level)
			if err != nil {
				return fmt.Errorf("bad log level value '%s': %+v", cfg.Log.Level, err)
			}
		} else {
			// set the log level implicitly
			switch v := cfg.CliOptions.Verbosity; {
			case v == 1:
				cfg.Log.LevelOpt = zapcore.InfoLevel
			case v >= 2:
				cfg.Log.LevelOpt = zapcore.DebugLevel
			default:
				cfg.Log.LevelOpt = zapcore.ErrorLevel
			}
		}
	}

	return nil
}

func readConfig(v *viper.Viper, configPath string) error {
	v.AutomaticEnv()
	v.SetEnvPrefix(internal.ApplicationName)
	// allow for nested options to be specified via environment variables
	// e.g. pod.context = APPNAME_POD_CONTEXT
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	// use explicitly the given user config
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err == nil {
			return nil
		}
		// don't fall through to other options if this fails
		return fmt.Errorf("unable to read config: %v", configPath)
	}

	// start searching for valid configs in order...

	// 1. look for .<appname>.yaml (in the current directory)
	v.AddConfigPath(".")
	v.SetConfigName(internal.ApplicationName)
	if err := v.ReadInConfig(); err == nil {
		return nil
	}

	// 2. look for .<appname>/config.yaml (in the current directory)
	v.AddConfigPath("." + internal.ApplicationName)
	v.SetConfigName("config")
	if err := v.ReadInConfig(); err == nil {
		return nil
	}

	// 3. look for ~/.<appname>.yaml
	home, err := homedir.Dir()
	if err == nil {
		v.AddConfigPath(home)
		v.SetConfigName("." + internal.ApplicationName)
		if err := v.ReadInConfig(); err == nil {
			return nil
		}
	}

	// 4. look for <appname>/config.yaml in xdg locations (starting with xdg home config dir, then moving upwards)
	v.AddConfigPath(path.Join(xdg.ConfigHome, internal.ApplicationName))
	for _, dir := range xdg.ConfigDirs {
		v.AddConfigPath(path.Join(dir, internal.ApplicationName))
	}
	v.SetConfigName("config")
	if err := v.ReadInConfig(); err == nil {
		return nil
	}

	return fmt.Errorf("application config not found")
}
