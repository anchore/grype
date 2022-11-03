package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/gookit/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"

	anchoreLogger "github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/internal/config"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/logger"
	"github.com/anchore/grype/internal/version"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/syft"
)

var (
	appConfig         *config.Application
	eventBus          *partybus.Bus
	eventSubscription *partybus.Subscription
)

func init() {
	cobra.OnInitialize(
		initRootCmdConfigOptions,
		initAppConfig,
		initLogging,
		logAppConfig,
		logAppVersion,
		initEventBus,
	)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_ = stderrPrintLnf(err.Error())
		os.Exit(1)
	}
}

func initRootCmdConfigOptions() {
	if err := bindRootConfigOptions(rootCmd.Flags()); err != nil {
		panic(err)
	}
}

func initAppConfig() {
	cfg, err := config.LoadApplicationConfig(viper.GetViper(), persistentOpts)
	if err != nil {
		fmt.Printf("failed to load application config: \n\t%+v\n", err)
		os.Exit(1)
	}
	appConfig = cfg
}

func initLogging() {
	enableConsole := (appConfig.Log.FileLocation == "" || appConfig.CliOptions.Verbosity > 0) && !appConfig.Quiet
	cfg := logger.LogrusConfig{
		EnableConsole: enableConsole,
		EnableFile:    appConfig.Log.FileLocation != "",
		Level:         appConfig.Log.LevelOpt,
		Structured:    appConfig.Log.Structured,
		FileLocation:  appConfig.Log.FileLocation,
	}

	logWrapper := logger.NewLogrusLogger(cfg)

	grype.SetLogger(logWrapper)

	// TODO: separate syft logger config until grype consumes new logger
	syftLoggerCfg := logrus.Config{
		EnableConsole: enableConsole,
		Level:         anchoreLogger.Level(appConfig.Log.LevelOpt.String()),
	}
	lw, err := logrus.New(syftLoggerCfg)
	if err != nil {
		panic(err)
	}
	syft.SetLogger(lw)
	stereoscope.SetLogger(&logger.LogrusNestedLogger{
		Logger: logWrapper.Logger.WithField("from-lib", "stereoscope"),
	})
}

func logAppConfig() {
	log.Debugf("application config:\n%+v", color.Magenta.Sprint(appConfig.String()))
}

func logAppVersion() {
	versionInfo := version.FromBuild()
	log.Infof("grype version: %s", versionInfo.Version)

	var fields map[string]interface{}
	bytes, err := json.Marshal(versionInfo)
	if err != nil {
		return
	}
	err = json.Unmarshal(bytes, &fields)
	if err != nil {
		return
	}

	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for idx, field := range keys {
		value := fields[field]
		branch := "├──"
		if idx == len(fields)-1 {
			branch = "└──"
		}
		log.Debugf("  %s %s: %s", branch, field, value)
	}
}

func initEventBus() {
	eventBus = partybus.NewBus()
	eventSubscription = eventBus.Subscribe()

	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	grype.SetBus(eventBus)
}
