package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/gookit/color"
	logrusUpstream "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/internal/config"
	"github.com/anchore/grype/internal/log"
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
	cfg := logrus.Config{
		EnableConsole: (appConfig.Log.FileLocation == "" || appConfig.CliOptions.Verbosity > 0) && !appConfig.Quiet,
		FileLocation:  appConfig.Log.FileLocation,
		Level:         appConfig.Log.Level,
	}

	if appConfig.Log.Structured {
		cfg.Formatter = &logrusUpstream.JSONFormatter{
			TimestampFormat:   "2006-01-02T15:04:05.000Z",
			DisableTimestamp:  false,
			DisableHTMLEscape: false,
			PrettyPrint:       false,
		}
	}

	logWrapper, err := logrus.New(cfg)
	if err != nil {
		// this is kinda circular, but we can't return an error... ¯\_(ツ)_/¯
		// I'm going to leave this here in case we one day have a different default logger other than the "discard" logger
		log.Error("unable to initialize logger: %+v", err)
		return
	}
	grype.SetLogger(logWrapper)
	syft.SetLogger(logWrapper.Nested("from-lib", "syft"))
	stereoscope.SetLogger(logWrapper.Nested("from-lib", "stereoscope"))
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
