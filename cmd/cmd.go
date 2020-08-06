package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/internal/config"
	"github.com/anchore/grype/internal/format"
	"github.com/anchore/grype/internal/logger"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/syft"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
	"gopkg.in/yaml.v2"
)

var appConfig *config.Application
var log *logrus.Logger
var cliOnlyOpts config.CliOnlyOptions
var eventBus *partybus.Bus
var eventSubscription *partybus.Subscription

func init() {
	setGlobalCliOptions()

	// read in config and setup logger
	cobra.OnInitialize(
		initAppConfig,
		initLogging,
		logAppConfig,
		initEventBus,
	)
}

func setGlobalCliOptions() {
	// setup global CLI options (available on all CLI commands)
	rootCmd.PersistentFlags().StringVarP(&cliOnlyOpts.ConfigPath, "config", "c", "", "application config file")

	flag := "quiet"
	rootCmd.PersistentFlags().BoolP(
		flag, "q", false,
		"suppress all logging output",
	)
	if err := viper.BindPFlag(flag, rootCmd.PersistentFlags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().CountVarP(&cliOnlyOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func initAppConfig() {
	cfg, err := config.LoadConfigFromFile(viper.GetViper(), &cliOnlyOpts)
	if err != nil {
		fmt.Printf("failed to load application config: \n\t%+v\n", err)
		os.Exit(1)
	}
	appConfig = cfg
}

func initLogging() {
	cfg := logger.LogrusConfig{
		EnableConsole: (appConfig.Log.FileLocation == "" || appConfig.CliOptions.Verbosity > 0) && !appConfig.Quiet,
		EnableFile:    appConfig.Log.FileLocation != "",
		Level:         appConfig.Log.LevelOpt,
		Structured:    appConfig.Log.Structured,
		FileLocation:  appConfig.Log.FileLocation,
	}

	logWrapper := logger.NewLogrusLogger(cfg)

	log = logWrapper.Logger
	grype.SetLogger(logWrapper)

	// add a structured field to all loggers of dependencies
	syft.SetLogger(&logger.LogrusNestedLogger{
		Logger: log.WithField("from-lib", "syft"),
	})
	stereoscope.SetLogger(&logger.LogrusNestedLogger{
		Logger: log.WithField("from-lib", "stereoscope"),
	})
}

func logAppConfig() {
	appCfgStr, err := yaml.Marshal(&appConfig)

	if err != nil {
		log.Debugf("Could not display application config: %+v", err)
	} else {
		log.Debugf("Application config:\n%+v", format.Magenta.Format(string(appCfgStr)))
	}
}

func initEventBus() {
	eventBus = partybus.NewBus()
	eventSubscription = eventBus.Subscribe()

	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	grype.SetBus(eventBus)
}
