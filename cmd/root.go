package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/imgbom/imgbom"
	_distro "github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/stereoscope"
	"github.com/anchore/vulnscan/internal"
	"github.com/anchore/vulnscan/internal/db"
	"github.com/anchore/vulnscan/internal/format"
	"github.com/anchore/vulnscan/vulnscan"
	"github.com/anchore/vulnscan/vulnscan/presenter"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   fmt.Sprintf("%s [IMAGE]", internal.ApplicationName),
	Short: "A vulnerability scanner tool", // TODO: add copy, add path-based scans
	Long: format.Tprintf(`Supports the following image sources:
    {{.appName}} yourrepo/yourimage:tag             defaults to using images from a docker daemon
    {{.appName}} docker://yourrepo/yourimage:tag    explicitly use a docker daemon
    {{.appName}} tar://path/to/yourimage.tar        use a tarball from disk
`, map[string]interface{}{
		"appName": internal.ApplicationName,
	}),
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runDefaultCmd(cmd, args))
	},
}

func init() {
	// setup CLI options specific to scanning an image

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
		flag, "o", "json",
		fmt.Sprintf("report output formatter, options=%v", presenter.Options),
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}
}

func runDefaultCmd(_ *cobra.Command, args []string) int {
	userImageStr := args[0]
	log.Infof("Fetching image '%s'", userImageStr)
	img, err := stereoscope.GetImage(userImageStr)
	if err != nil {
		log.Errorf("could not fetch image '%s': %w", userImageStr, err)
		return 1
	}
	defer stereoscope.Cleanup()

	log.Info("Cataloging image")
	catalog, err := imgbom.CatalogImage(img, appConfig.ScopeOpt)
	if err != nil {
		log.Errorf("could not catalog image: %w", err)
		return 1
	}

	osObj := _distro.Identify(img)
	if osObj == nil {
		// prevent moving forward with unknown distros for now, revisit later
		log.Error("unable to detect distro type for accurate vulnerability matching")
		return 1
	}

	store := db.GetStore()
	provider := vulnerability.NewProviderFromStore(store)

	results := vulnscan.FindAllVulnerabilities(provider, *osObj, catalog)
	outputOption := viper.GetString("output")

	presenterType := presenter.ParseOption(outputOption)
	if presenterType == presenter.UnknownPresenter {
		log.Errorf("cannot find an output presenter for option: %s", outputOption)
		return 1
	}

	err = presenter.GetPresenter(presenterType).Present(os.Stdout, catalog, results)
	if err != nil {
		log.Errorf("could not format catalog results: %w", err)
		return 1
	}

	return 0
}
