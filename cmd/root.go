package cmd

import (
	"fmt"
	"os"
	"sync"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/grypeerr"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/config"
	"github.com/anchore/grype/internal/format"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/ui"
	"github.com/anchore/grype/internal/version"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/syft/source"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"

	grypeDb "github.com/anchore/grype-db/pkg/db/v3"
)

var persistentOpts = config.CliOnlyOptions{}

var ignoreNonFixedMatches = []match.IgnoreRule{
	{FixState: string(grypeDb.NotFixedState)},
	{FixState: string(grypeDb.WontFixState)},
	{FixState: string(grypeDb.UnknownFixState)},
}

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
    {{.appName}} registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)

You can also pipe in Syft JSON directly:
	syft yourimage:tag -o json | {{.appName}}

`, map[string]interface{}{
			"appName": internal.ApplicationName,
		}),
		Args:          validateRootArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if appConfig.Dev.ProfileCPU {
				defer profile.Start(profile.CPUProfile).Stop()
			} else if appConfig.Dev.ProfileMem {
				defer profile.Start(profile.MemProfile).Stop()
			}

			return rootExec(cmd, args)
		},
		ValidArgsFunction: dockerImageValidArgsFunction,
	}
)

func init() {
	setGlobalCliOptions()
	setRootFlags(rootCmd.Flags())
}

func setGlobalCliOptions() {
	// setup global CLI options (available on all CLI commands)
	rootCmd.PersistentFlags().StringVarP(&persistentOpts.ConfigPath, "config", "c", "", "application config file")

	flag := "quiet"
	rootCmd.PersistentFlags().BoolP(
		flag, "q", false,
		"suppress all logging output",
	)
	if err := viper.BindPFlag(flag, rootCmd.PersistentFlags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().CountVarP(&persistentOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
}

func setRootFlags(flags *pflag.FlagSet) {
	flags.StringP(
		"scope", "s", source.SquashedScope.String(),
		fmt.Sprintf("selection of layers to analyze, options=%v", source.AllScopes),
	)

	flags.StringP(
		"output", "o", "",
		fmt.Sprintf("report output formatter, formats=%v", presenter.AvailableFormats),
	)

	flags.StringP(
		"file", "", "",
		"file to write the report output to (default is STDOUT)",
	)

	flags.StringP("template", "t", "", "specify the path to a Go template file ("+
		"requires 'template' output to be selected)")

	flags.StringP(
		"fail-on", "f", "",
		fmt.Sprintf("set the return code to 1 if a vulnerability is found with a severity >= the given severity, options=%v", vulnerability.AllSeverities),
	)

	flags.BoolP(
		"only-fixed", "", false,
		"ignore matches for vulnerabilities that are not fixed",
	)
}

func bindRootConfigOptions(flags *pflag.FlagSet) error {
	if err := viper.BindPFlag("scope", flags.Lookup("scope")); err != nil {
		return err
	}

	if err := viper.BindPFlag("output", flags.Lookup("output")); err != nil {
		return err
	}

	if err := viper.BindPFlag("file", flags.Lookup("file")); err != nil {
		return err
	}

	if err := viper.BindPFlag("output-template-file", flags.Lookup("template")); err != nil {
		return err
	}

	if err := viper.BindPFlag("fail-on-severity", flags.Lookup("fail-on")); err != nil {
		return err
	}

	if err := viper.BindPFlag("only-fixed", flags.Lookup("only-fixed")); err != nil {
		return err
	}

	return nil
}

func rootExec(_ *cobra.Command, args []string) error {
	// we may not be provided an image if the user is piping in SBOM input
	var userInput string
	if len(args) > 0 {
		userInput = args[0]
	}

	reporter, closer, err := reportWriter()
	defer func() {
		if err := closer(); err != nil {
			log.Warnf("unable to write to report destination: %+v", err)
		}
	}()

	if err != nil {
		return err
	}

	return eventLoop(
		startWorker(userInput, appConfig.FailOnSeverity),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(appConfig.CliOptions.Verbosity > 0, appConfig.Quiet, reporter)...,
	)
}

// nolint:funlen
func startWorker(userInput string, failOnSeverity *vulnerability.Severity) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		presenterConfig, err := presenter.ValidatedConfig(appConfig.Output, appConfig.OutputTemplateFile)
		if err != nil {
			errs <- err
			return
		}

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
		var dbStatus *db.Status
		var packages []pkg.Package
		var context pkg.Context
		var wg = &sync.WaitGroup{}

		wg.Add(2)

		go func() {
			defer wg.Done()
			log.Debug("loading DB")
			provider, metadataProvider, dbStatus, err = grype.LoadVulnerabilityDB(appConfig.DB.ToCuratorConfig(), appConfig.DB.AutoUpdate)
			if err != nil {
				errs <- fmt.Errorf("failed to load vulnerability db: %w", err)
			}
			if dbStatus == nil {
				errs <- fmt.Errorf("unable to determine DB status")
			}
		}()

		go func() {
			defer wg.Done()
			log.Debugf("gathering packages")
			packages, context, err = pkg.Provide(userInput, appConfig.ScopeOpt, appConfig.Registry.ToOptions())
			if err != nil {
				errs <- fmt.Errorf("failed to catalog: %w", err)
			}
		}()

		wg.Wait()
		if err != nil {
			return
		}

		if appConfig.OnlyFixed {
			appConfig.Ignore = append(appConfig.Ignore, ignoreNonFixedMatches...)
		}

		allMatches := grype.FindVulnerabilitiesForPackage(provider, context.Distro, packages...)
		remainingMatches, ignoredMatches := match.ApplyIgnoreRules(allMatches, appConfig.Ignore)

		if count := len(ignoredMatches); count > 0 {
			log.Infof("Ignoring %d matches due to user-provided ignore rules", count)
		}

		// determine if there are any severities >= to the max allowable severity (which is optional).
		// note: until the shared file lock in sqlittle is fixed the sqlite DB cannot be access concurrently,
		// implying that the fail-on-severity check must be done before sending the presenter object.
		if hitSeverityThreshold(failOnSeverity, remainingMatches, metadataProvider) {
			errs <- grypeerr.ErrAboveSeverityThreshold
		}

		bus.Publish(partybus.Event{
			Type:  event.VulnerabilityScanningFinished,
			Value: presenter.GetPresenter(presenterConfig, remainingMatches, ignoredMatches, packages, context, metadataProvider, appConfig, dbStatus),
		})
	}()
	return errs
}

func validateRootArgs(cmd *cobra.Command, args []string) error {
	// the user must specify at least one argument OR wait for input on stdin IF it is a pipe
	if len(args) == 0 && !internal.IsPipedInput() {
		// return an error with no message for the user, which will implicitly show the help text (but no specific error)
		return fmt.Errorf("")
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}

// hitSeverityThreshold indicates if there are any severities >= to the max allowable severity (which is optional)
func hitSeverityThreshold(thresholdSeverity *vulnerability.Severity, matches match.Matches, metadataProvider vulnerability.MetadataProvider) bool {
	if thresholdSeverity != nil {
		var maxDiscoveredSeverity vulnerability.Severity
		for m := range matches.Enumerate() {
			metadata, err := metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.Namespace)
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
