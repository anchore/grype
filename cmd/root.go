package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/pprof"
	"strings"
	"sync"

	"github.com/gookit/color"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/grypeerr"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/format"
	"github.com/anchore/grype/internal/ui"
	"github.com/anchore/grype/internal/version"
	"github.com/anchore/syft/syft/source"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	scopeFlag    = "scope"
	outputFlag   = "output"
	failOnFlag   = "fail-on"
	templateFlag = "template"
)

var (
	rootCmd = &cobra.Command{
		Use:   fmt.Sprintf("%s [IMAGE]", internal.ApplicationName),
		Short: "A vulnerability scanner for container images and filesystems",
		Long: format.Tprintf(`
Supports the following image sources:
    {{.appName}} yourrepo/yourimage:tag     defaults to using images from a Docker daemon
    {{.appName}} path/to/yourproject        a Docker tar, OCI tar, OCI directory, or generic filesystem directory

You can also explicitly specify the scheme to use:
    {{.appName}} docker:yourrepo/yourimage:tag          explicitly use the Docker daemon
    {{.appName}} docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
    {{.appName}} oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Podman or otherwise)
    {{.appName}} oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    {{.appName}} dir:path/to/yourproject                read directly from a path on disk (any directory)
    {{.appName}} sbom:path/to/syft.json                 read Syft JSON from path on disk

You can also pipe in Syft JSON directly:
	syft yourimage:tag -o json | {{.appName}}

`, map[string]interface{}{
			"appName": internal.ApplicationName,
		}),
		Args: validateRootArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if appConfig.Dev.ProfileCPU {
				stopProfile := createCPUProfile()
				defer stopProfile()
			}

			if appConfig.CheckForAppUpdate {
				checkForAppUpdate()
			}

			presenter, err := presenter.GetPresenter(appConfig.Output, appConfig.OutputTemplateFile)
			if err != nil {
				reportAndExitWithError(err)
			}

			userInput := getUserInputForAnalysis(args)
			analysis, err := analyzeWithUI(userInput)
			if err != nil {
				reportAndExitWithError(err)
			}

			// determine if there are any severities >= to the max allowable severity (which is optional).
			if hitSeverityThreshold(appConfig.FailOnSeverity, analysis) {
				// deferring because we want the user to see this error easily, even when the app
				// produces a large amount of output
				defer reportError(grypeerr.ErrAboveSeverityThreshold)
			}

			err = presenter.Present(os.Stdout, analysis)
			if err != nil {
				reportAndExitWithError(err)
			}
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			// Since we use ValidArgsFunction, Cobra will call this AFTER having parsed all flags and arguments provided
			dockerImageRepoTags, err := listLocalDockerImages(toComplete)
			if err != nil {
				// Indicates that an error occurred and completions should be ignored
				return []string{"completion failed"}, cobra.ShellCompDirectiveError
			}
			if len(dockerImageRepoTags) == 0 {
				return []string{"no docker images found"}, cobra.ShellCompDirectiveError
			}
			// ShellCompDirectiveDefault indicates that the shell will perform its default behavior after completions have
			// been provided (without implying other possible directives)
			return dockerImageRepoTags, cobra.ShellCompDirectiveDefault
		},
	}
)

func getUserInputForAnalysis(args []string) string {
	// we may not be provided an image if the user is piping in SBOM input
	if len(args) == 1 {
		return args[0]
	}

	return ""
}

// createCPUProfile starts a CPU profile and returns a function to stop the profile.
func createCPUProfile() func() {
	f, err := os.Create("cpu.profile")
	if err != nil {
		log.Errorf("unable to create CPU profile: %+v", err)
		return nil
	}

	err = pprof.StartCPUProfile(f)
	if err != nil {
		log.Errorf("unable to start CPU profile: %+v", err)
	}
	return pprof.StopCPUProfile
}

// reportAndExitWithError reports the given error to the user and then exits non-zero.
func reportAndExitWithError(err error) {
	reportError(err)
	os.Exit(1)
}

// reportError reports the given error to the user (without exiting).
func reportError(err error) {
	var grypeErr grypeerr.ExpectedErr
	if errors.As(err, &grypeErr) {
		fmt.Fprintln(os.Stderr, format.Red.Format(grypeErr.Error()))
	} else {
		log.Errorf(err.Error())
	}
}

func checkForAppUpdate() {
	isAvailable, newVersion, err := version.IsUpdateAvailable()
	if err != nil {
		log.Errorf(err.Error())
	}

	if !isAvailable {
		log.Debugf("No new %s update available", internal.ApplicationName)
		return
	}

	log.Infof("New version of %s is available: %s", internal.ApplicationName, newVersion)

	// TODO: Should we conditionally not show this?
	fmt.Println(color.Magenta.Sprintf("New version of %s is available: %s", internal.ApplicationName, newVersion))
}

func validateRootArgs(cmd *cobra.Command, args []string) error {
	// the user must specify at least one argument OR wait for input on stdin IF it is a pipe
	if len(args) == 0 && !internal.IsPipedInput() {
		// return an error with no message for the user, which will implicitly show the help text (but no specific error)
		return fmt.Errorf("")
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}

func init() {
	// setup CLI options specific to scanning an image

	// scan options
	flag := scopeFlag
	rootCmd.Flags().StringP(
		scopeFlag, "s", source.SquashedScope.String(),
		fmt.Sprintf("selection of layers to analyze, options=%v", source.AllScopes),
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	// output & formatting options
	flag = outputFlag
	rootCmd.Flags().StringP(
		flag, "o", "",
		fmt.Sprintf("report output formatter, formats=%v", presenter.AvailableFormats),
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = templateFlag
	rootCmd.Flags().StringP(flag, "t", "", "specify the path to a Go template file ("+
		"requires 'template' output to be selected)")
	if err := viper.BindPFlag("output-template-file", rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = failOnFlag
	rootCmd.Flags().StringP(
		flag, "f", "",
		fmt.Sprintf("set the return code to 1 if a vulnerability is found with a severity >= the given severity, options=%v", vulnerability.AllSeverities),
	)
	if err := viper.BindPFlag("fail-on-severity", rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}
}

func analyzeWithUI(userInput string) (grype.Analysis, error) {
	analysisEvents := startAnalysis(userInput)

	ux := ui.Select(appConfig.CliOptions.Verbosity > 0, appConfig.Quiet)
	ctxForUX, terminateUX := context.WithCancel(context.Background())
	defer terminateUX()

	analysisErrors := make(chan error)
	uxError := ux(ctxForUX, analysisErrors, eventSubscription)

	//nolint:gosimple
	for {
		select {
		case e := <-analysisEvents:
			if e.err != nil {
				analysisErrors <- e.err
				continue
			}

			terminateUX()

			// Wait for UX to close out
			err := <-uxError

			if err != nil {
				return grype.Analysis{}, err
			}

			return e.analysis, nil
		}
	}
}

type analysisEvent struct {
	err      error
	analysis grype.Analysis
}

func startAnalysis(userInput string) <-chan analysisEvent {
	events := make(chan analysisEvent)
	go func() {
		var provider vulnerability.Provider
		var metadataProvider vulnerability.MetadataProvider
		var packages []pkg.Package
		var context pkg.Context
		var err error
		var wg = &sync.WaitGroup{}

		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Debug("loading DB")
			provider, metadataProvider, err = grype.LoadVulnerabilityDb(appConfig.Db.ToCuratorConfig(), appConfig.Db.AutoUpdate)
			if err != nil {
				events <- analysisEvent{err: fmt.Errorf("failed to load vulnerability db: %w", err)}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Debugf("gathering packages")
			packages, context, err = pkg.Provide(userInput, appConfig.ScopeOpt)
			if err != nil {
				events <- analysisEvent{err: fmt.Errorf("failed to catalog: %w", err)}
			}
		}()

		wg.Wait()
		if err != nil {
			return
		}

		matches := grype.FindVulnerabilitiesForPackage(provider, context.Distro, packages...)
		analysis := grype.Analysis{
			Matches:          matches,
			Packages:         packages,
			Context:          context,
			MetadataProvider: metadataProvider,
			AppConfig:        appConfig,
		}
		events <- analysisEvent{analysis: analysis}
	}()
	return events
}

// hitSeverityThreshold indicates if there are any severities >= to the max allowable severity (which is optional)
func hitSeverityThreshold(thresholdSeverity *vulnerability.Severity, analysis grype.Analysis) bool {
	if thresholdSeverity == nil {
		return false
	}

	var maxDiscoveredSeverity vulnerability.Severity
	for m := range analysis.Matches.Enumerate() {
		metadata, err := analysis.MetadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.RecordSource)
		if err != nil {
			continue
		}
		severity := vulnerability.ParseSeverity(metadata.Severity)
		if severity > maxDiscoveredSeverity {
			maxDiscoveredSeverity = severity
		}
	}

	return maxDiscoveredSeverity >= *thresholdSeverity
}

func listLocalDockerImages(prefix string) ([]string, error) {
	var repoTags = make([]string, 0)
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return repoTags, err
	}

	// Only want to return tagged images
	imageListArgs := filters.NewArgs()
	imageListArgs.Add("dangling", "false")
	images, err := cli.ImageList(ctx, types.ImageListOptions{All: false, Filters: imageListArgs})
	if err != nil {
		return repoTags, err
	}

	for _, image := range images {
		// image may have multiple tags
		for _, tag := range image.RepoTags {
			if strings.HasPrefix(tag, prefix) {
				repoTags = append(repoTags, tag)
			}
		}
	}
	return repoTags, nil
}
