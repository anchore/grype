package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/pprof"
	"strings"
	"sync"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/grypeerr"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/format"
	"github.com/anchore/grype/internal/ui"
	"github.com/anchore/grype/internal/version"
	"github.com/anchore/syft/syft/source"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

const (
	scopeFlag  = "scope"
	outputFlag = "output"
	FailOnFlag = "fail-on"
)

var rootCmd = &cobra.Command{
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
			var grypeErr grypeerr.ExpectedErr
			if errors.As(err, &grypeErr) {
				fmt.Fprintln(os.Stderr, format.Red.Format(grypeErr.Error()))
			} else {
				log.Errorf(err.Error())
			}
			os.Exit(1)
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
		flag, "o", presenter.TablePresenter.String(),
		fmt.Sprintf("report output formatter, options=%v", presenter.Options),
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = FailOnFlag
	rootCmd.Flags().StringP(
		flag, "f", "",
		fmt.Sprintf("set the return code to 1 if a vulnerability is found with a severity >= the given severity, options=%v", vulnerability.AllSeverities),
	)
	if err := viper.BindPFlag("fail-on-severity", rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}
}

// nolint:funlen
func startWorker(userInput string, failOnSeverity *vulnerability.Severity) <-chan error {
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
		var metadataProvider vulnerability.MetadataProvider
		var packages []pkg.Package
		var context pkg.Context
		var err error
		var wg = &sync.WaitGroup{}

		wg.Add(2)

		go func() {
			defer wg.Done()
			log.Debug("loading DB")
			provider, metadataProvider, err = grype.LoadVulnerabilityDb(appConfig.Db.ToCuratorConfig(), appConfig.Db.AutoUpdate)
			if err != nil {
				errs <- fmt.Errorf("failed to load vulnerability db: %w", err)
			}
		}()

		go func() {
			defer wg.Done()
			log.Debugf("gathering packages")
			packages, context, err = pkg.Provide(userInput, appConfig.ScopeOpt)
			if err != nil {
				errs <- fmt.Errorf("failed to catalog: %w", err)
			}
		}()

		wg.Wait()
		if err != nil {
			return
		}

		matches := grype.FindVulnerabilitiesForPackage(provider, context.Distro, packages...)

		// determine if there are any severities >= to the max allowable severity (which is optional).
		// note: until the shared file lock in sqlittle is fixed the sqlite DB cannot be access concurrently,
		// implying that the fail-on-severity check must be done before sending the presenter object.
		if hitSeverityThreshold(failOnSeverity, matches, metadataProvider) {
			errs <- grypeerr.ErrAboveSeverityThreshold
		}

		bus.Publish(partybus.Event{
			Type:  event.VulnerabilityScanningFinished,
			Value: presenter.GetPresenter(appConfig.PresenterOpt, matches, packages, context, metadataProvider),
		})
	}()
	return errs
}

func runDefaultCmd(_ *cobra.Command, args []string) error {
	// we may not be provided an image if the user is piping in SBOM input
	var userInput string
	if len(args) > 0 {
		userInput = args[0]
	}
	errs := startWorker(userInput, appConfig.FailOnSeverity)
	ux := ui.Select(appConfig.CliOptions.Verbosity > 0, appConfig.Quiet)
	return ux(errs, eventSubscription)
}

// hitSeverityThreshold indicates if there are any severities >= to the max allowable severity (which is optional)
func hitSeverityThreshold(thresholdSeverity *vulnerability.Severity, matches match.Matches, metadataProvider vulnerability.MetadataProvider) bool {
	if thresholdSeverity != nil {
		var maxDiscoveredSeverity vulnerability.Severity
		for m := range matches.Enumerate() {
			metadata, err := metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.RecordSource)
			if err != nil {
				continue
			}
			severity := vulnerability.ParseSeverity(metadata.Severity)
			if severity > maxDiscoveredSeverity {
				maxDiscoveredSeverity = severity
			}
		}

		if maxDiscoveredSeverity >= *thresholdSeverity {
			return true
		}
	}
	return false
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
