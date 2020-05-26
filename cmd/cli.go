package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/vulnscan/internal/config"
	"github.com/spf13/viper"
)

var cliOpts = config.CliOnlyOptions{}

func setCliOptions() {
	rootCmd.PersistentFlags().StringVarP(&cliOpts.ConfigPath, "config", "c", "", "application config file")

	// scan options
	flag := "scope"
	rootCmd.Flags().StringP(
		"scope", "s", scope.AllLayersScope.String(),
		fmt.Sprintf("selection of layers to analyze, options=%v", scope.Options))
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	// output & formatting options
	flag = "output"
	rootCmd.Flags().StringP(
		// TODO: default option
		flag, "o", "text",
		// TODO: show all options
		fmt.Sprintf("report output formatter, options=%v", []string{}),
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = "quiet"
	rootCmd.Flags().BoolP(
		flag, "q", false,
		"suppress all logging output",
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	rootCmd.Flags().CountVarP(&cliOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
}
