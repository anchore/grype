package cmd

import (
	"fmt"
	"os"
	"runtime/pprof"

	"github.com/anchore/imgbom/imgbom"
	_distro "github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/vulnscan/internal"
	"github.com/anchore/vulnscan/internal/format"
	"github.com/anchore/vulnscan/internal/version"
	"github.com/anchore/vulnscan/vulnscan"
	"github.com/anchore/vulnscan/vulnscan/db"
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
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if appConfig.Dev.ProfileCPU {
			f, err := os.Create("cpu.profile")
			if err != nil {
				log.Errorf("unable to create CPU profile: %+v", err)
			} else {
				err := pprof.StartCPUProfile(f)
				if err != nil {
					log.Errorf("unable to start CPU profile: %+v", err)
				}
			}
		}

		exitCode := runDefaultCmd(cmd, args)

		if appConfig.Dev.ProfileCPU {
			pprof.StopCPUProfile()
		}

		os.Exit(exitCode)
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

// nolint:funlen
func runDefaultCmd(_ *cobra.Command, args []string) int {
	if appConfig.CheckForAppUpdate {
		isAvailable, newVersion, err := version.IsUpdateAvailable()
		if err != nil {
			log.Errorf(err.Error())
		}
		if isAvailable {
			log.Infof("New version of %s is available: %s", internal.ApplicationName, newVersion)
		} else {
			log.Debugf("No new %s update available", internal.ApplicationName)
		}
	}

	userImageStr := args[0]
	scope, cleanup, err := imgbom.NewScope(userImageStr, appConfig.ScopeOpt)
	if err != nil {
		log.Errorf("could not produce catalog: %w", err)
		return 1
	}
	defer cleanup()

	log.Info("creating catalog")
	catalog, err := imgbom.Catalog(scope)
	if err != nil {
		log.Errorf("could not produce catalog: %w", err)
	}

	osObj := _distro.Identify(scope)

	dbCurator, err := db.NewCurator(appConfig.Db.ToCuratorConfig())
	if err != nil {
		log.Errorf("could not curate database: %+v", err)
		return 1
	}

	if appConfig.Db.UpdateOnStartup {
		updateAvailable, updateEntry, err := dbCurator.IsUpdateAvailable()
		if err != nil {
			// TODO: should this be so fatal? we can certainly continue with a warning...
			log.Errorf("unable to check for vulnerability database update: %+v", err)
			return 1
		}
		if updateAvailable {
			err = dbCurator.UpdateTo(updateEntry)
			if err != nil {
				log.Errorf("unable to update vulnerability database: %+v", err)
				return 1
			}
		}
	}

	store, err := dbCurator.GetStore()
	if err != nil {
		log.Errorf("failed to load vulnerability database: %+v", err)
		return 1
	}

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
		log.Errorf("could not format catalog results: %+v", err)
		return 1
	}

	return 0
}
