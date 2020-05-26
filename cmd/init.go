package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/vulnscan/internal/config"
	"github.com/anchore/vulnscan/internal/format"
	"github.com/anchore/vulnscan/internal/logger"
	"github.com/anchore/vulnscan/vulnscan"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

var appConfig *config.Application
var log *zap.SugaredLogger

func initAppConfig() {
	cfg, err := config.LoadConfigFromFile(viper.GetViper(), &cliOpts)
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
