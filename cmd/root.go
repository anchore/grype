package cmd

import (
	"fmt"
	"os"
	"runtime/pprof"
	"sync"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/format"
	"github.com/anchore/grype/internal/ui"
	"github.com/anchore/grype/internal/version"
	"github.com/anchore/syft/syft/scope"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

var rootCmd = &cobra.Command{
	Use:   fmt.Sprintf("%s [IMAGE]", internal.ApplicationName),
	Short: "A vulnerability scanner for container images and filesystems", // TODO: add copy, add path-based scans
	Long: format.Tprintf(`Supports the following image sources:
    {{.appName}} yourrepo/yourimage:tag             defaults to using images from a docker daemon
    {{.appName}} dir://path/to/yourrepo             do a directory scan
    {{.appName}} docker://yourrepo/yourimage:tag    explicitly use a docker daemon
    {{.appName}} tar://path/to/yourimage.tar        use a tarball from disk
`, map[string]interface{}{
		"appName": internal.ApplicationName,
	}),
	Args: cobra.MaximumNArgs(1),
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
		if len(args) == 0 {
			err := cmd.Help()
			if err != nil {
				log.Errorf(err.Error())
				os.Exit(1)
			}
			os.Exit(1)
		}
		err := runDefaultCmd(cmd, args)

		if appConfig.Dev.ProfileCPU {
			pprof.StopCPUProfile()
		}

		if err != nil {
			log.Errorf(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	// setup CLI options specific to scanning an image

	// scan options
	flag := "scope"
	rootCmd.Flags().StringP(
		"scope", "s", scope.AllLayersScope.String(),
		fmt.Sprintf("selection of layers to analyze, options=%v", scope.Options),
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	// output & formatting options
	flag = "output"
	rootCmd.Flags().StringP(
		flag, "o", presenter.TablePresenter.String(),
		fmt.Sprintf("report output formatter, options=%v", presenter.Options),
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}
}

func startWorker(userInput string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		if appConfig.CheckForAppUpdate {
			isAvailable, newVersion, err := version.IsUpdateAvailable()
			if err != nil {
				log.Errorf(err.Error())
			}
			if isAvailable {
				log.Infof("New version of %s is available: %s", internal.ApplicationName, newVersion)

				bus.Publish(partybus.Event{
					Type:  event.AppUpdateAvailable,
					Value: newVersion,
				})
			} else {
				log.Debugf("No new %s update available", internal.ApplicationName)
			}
		}

		var provider vulnerability.Provider
		var catalog *pkg.Catalog
		var theDistro *distro.Distro
		var err error
		var wg = &sync.WaitGroup{}

		wg.Add(2)

		go func() {
			defer wg.Done()
			provider, err = grype.LoadVulnerabilityDb(appConfig.Db.ToCuratorConfig(), appConfig.Db.AutoUpdate)
			if err != nil {
				errs <- fmt.Errorf("failed to load vulnerability db: %w", err)
			}
		}()

		go func() {
			defer wg.Done()
			catalog, _, theDistro, err = syft.Catalog(userInput, appConfig.ScopeOpt)
			if err != nil {
				errs <- fmt.Errorf("failed to catalog: %w", err)
			}
		}()

		wg.Wait()
		if err != nil {
			return
		}

		results := grype.FindVulnerabilitiesForCatalog(provider, *theDistro, catalog)

		bus.Publish(partybus.Event{
			Type:  event.VulnerabilityScanningFinished,
			Value: presenter.GetPresenter(appConfig.PresenterOpt, results, catalog),
		})
	}()
	return errs
}

func runDefaultCmd(_ *cobra.Command, args []string) error {
	userInput := args[0]
	errs := startWorker(userInput)
	ux := ui.Select(appConfig.CliOptions.Verbosity > 0, appConfig.Quiet)
	return ux(errs, eventSubscription)
}
