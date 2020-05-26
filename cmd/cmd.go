package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/vulnscan/internal/config"
	"github.com/anchore/vulnscan/internal/format"
	"github.com/anchore/vulnscan/internal/logger"
	"github.com/anchore/vulnscan/vulnscan"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

var appConfig *config.Application
var log *zap.SugaredLogger
var cliOnlyOpts config.CliOnlyOptions

func init() {
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

	// read in config and setup logger
	cobra.OnInitialize(initAppConfig)
	cobra.OnInitialize(initLogging)
	cobra.OnInitialize(logAppConfig)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Errorf("could not start application: %w", err)
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
	config := logger.LogConfig{
		EnableConsole: (appConfig.Log.FileLocation == "" || appConfig.CliOptions.Verbosity > 0) && !appConfig.Quiet,
		EnableFile:    appConfig.Log.FileLocation != "",
		Level:         appConfig.Log.LevelOpt,
		Structured:    appConfig.Log.Structured,
		FileLocation:  appConfig.Log.FileLocation,
	}

	logWrapper := logger.NewZapLogger(config)
	log = logWrapper.Logger
	vulnscan.SetLogger(logWrapper)
	imgbom.SetLogger(logWrapper)
}

func logAppConfig() {
	appCfgStr, err := yaml.Marshal(&appConfig)

	if err != nil {
		log.Debugf("Could not display application config: %+v", err)
	} else {
		log.Debugf("Application config:\n%+v", format.Magenta.Format(string(appCfgStr)))
	}
}
