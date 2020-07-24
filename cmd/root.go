package cmd

import (
	"fmt"
	"os"
	"runtime/pprof"

	"github.com/anchore/syft/syft/scope"
	"github.com/anchore/vulnscan/internal"
	"github.com/anchore/vulnscan/internal/format"
	"github.com/anchore/vulnscan/vulnscan"
	"github.com/anchore/vulnscan/vulnscan/presenter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   fmt.Sprintf("%s [IMAGE]", internal.ApplicationName),
	Short: "A vulnerability scanner for container images and filesystems", // TODO: add copy, add path-based scans
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
		flag, "o", presenter.JSONPresenter.String(),
		fmt.Sprintf("report output formatter, options=%v", presenter.Options),
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}
}

func runDefaultCmd(_ *cobra.Command, args []string) error {
	userImageStr := args[0]

	provider, err := vulnscan.LoadVulnerabilityDb(appConfig.Db.ToCuratorConfig(), appConfig.Db.AutoUpdate)
	if err != nil {
		return fmt.Errorf("failed to load vulnerability db: %w", err)
	}

	results, catalog, _, err := vulnscan.FindVulnerabilities(provider, userImageStr, appConfig.ScopeOpt)
	if err != nil {
		return fmt.Errorf("failed to find vulnerabilities: %w", err)
	}

	if err = presenter.GetPresenter(appConfig.PresenterOpt).Present(os.Stdout, catalog, results); err != nil {
		return fmt.Errorf("could not format catalog results: %w", err)
	}

	return nil
}
