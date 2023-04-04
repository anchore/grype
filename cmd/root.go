package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	grypeDb "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/grypeerr"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/config"
	"github.com/anchore/grype/internal/format"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/ui"
	"github.com/anchore/grype/internal/version"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var persistentOpts = config.CliOnlyOptions{}

var ignoreNonFixedMatches = []match.IgnoreRule{
	{FixState: string(grypeDb.NotFixedState)},
	{FixState: string(grypeDb.WontFixState)},
	{FixState: string(grypeDb.UnknownFixState)},
}

var ignoreFixedMatches = []match.IgnoreRule{
	{FixState: string(grypeDb.FixedState)},
}

var (
	rootCmd = &cobra.Command{
		Use:   fmt.Sprintf("%s [IMAGE]", internal.ApplicationName),
		Short: "A vulnerability scanner for container images, filesystems, and SBOMs",
		Long: format.Tprintf(`A vulnerability scanner for container images, filesystems, and SBOMs.

Supports the following image sources:
    {{.appName}} yourrepo/yourimage:tag             defaults to using images from a Docker daemon
    {{.appName}} path/to/yourproject                a Docker tar, OCI tar, OCI directory, SIF container, or generic filesystem directory

You can also explicitly specify the scheme to use:
    {{.appName}} podman:yourrepo/yourimage:tag          explicitly use the Podman daemon
    {{.appName}} docker:yourrepo/yourimage:tag          explicitly use the Docker daemon
    {{.appName}} docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
    {{.appName}} oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Podman or otherwise)
    {{.appName}} oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    {{.appName}} singularity:path/to/yourimage.sif      read directly from a Singularity Image Format (SIF) container on disk
    {{.appName}} dir:path/to/yourproject                read directly from a path on disk (any directory)
    {{.appName}} sbom:path/to/syft.json                 read Syft JSON from path on disk
    {{.appName}} registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
    {{.appName}} purl:path/to/purl/file                 read a newline separated file of purls from a path on disk

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
		fmt.Sprintf("report output formatter, formats=%v, deprecated formats=%v", presenter.AvailableFormats, presenter.DeprecatedFormats),
	)

	flags.StringP(
		"file", "", "",
		"file to write the report output to (default is STDOUT)",
	)

	flags.StringP(
		"name", "", "",
		"set the name of the target being analyzed",
	)

	flags.StringP(
		"distro", "", "",
		"distro to match against in the format: <distro>:<version>",
	)

	flags.BoolP(
		"add-cpes-if-none", "", false,
		"generate CPEs for packages with no CPE data",
	)

	flags.StringP("template", "t", "", "specify the path to a Go template file ("+
		"requires 'template' output to be selected)")

	flags.StringP(
		"fail-on", "f", "",
		fmt.Sprintf("set the return code to 1 if a vulnerability is found with a severity >= the given severity, options=%v", vulnerability.AllSeverities()),
	)

	flags.BoolP(
		"only-fixed", "", false,
		"ignore matches for vulnerabilities that are not fixed",
	)

	flags.BoolP(
		"only-notfixed", "", false,
		"ignore matches for vulnerabilities that are fixed",
	)

	flags.BoolP(
		"by-cve", "", false,
		"orient results by CVE instead of the original vulnerability ID when possible",
	)

	flags.BoolP(
		"show-suppressed", "", false,
		"show suppressed/ignored vulnerabilities in the output (only supported with table output format)",
	)

	flags.StringArrayP(
		"exclude", "", nil,
		"exclude paths from being scanned using a glob expression",
	)

	flags.StringP(
		"platform", "", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')",
	)
}

//nolint:revive
func bindRootConfigOptions(flags *pflag.FlagSet) error {
	if err := viper.BindPFlag("search.scope", flags.Lookup("scope")); err != nil {
		return err
	}

	if err := viper.BindPFlag("output", flags.Lookup("output")); err != nil {
		return err
	}

	if err := viper.BindPFlag("file", flags.Lookup("file")); err != nil {
		return err
	}

	if err := viper.BindPFlag("distro", flags.Lookup("distro")); err != nil {
		return err
	}

	if err := viper.BindPFlag("add-cpes-if-none", flags.Lookup("add-cpes-if-none")); err != nil {
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

	if err := viper.BindPFlag("only-notfixed", flags.Lookup("only-notfixed")); err != nil {
		return err
	}

	if err := viper.BindPFlag("by-cve", flags.Lookup("by-cve")); err != nil {
		return err
	}

	if err := viper.BindPFlag("show-suppressed", flags.Lookup("show-suppressed")); err != nil {
		return err
	}

	if err := viper.BindPFlag("exclude", flags.Lookup("exclude")); err != nil {
		return err
	}

	if err := viper.BindPFlag("platform", flags.Lookup("platform")); err != nil {
		return err
	}

	if err := viper.BindPFlag("name", flags.Lookup("name")); err != nil {
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
		ui.Select(isVerbose(), appConfig.Quiet, reporter)...,
	)
}

func isVerbose() (result bool) {
	isPipedInput, err := internal.IsPipedInput()
	if err != nil {
		// since we can't tell if there was piped input we assume that there could be to disable the ETUI
		log.Warnf("unable to determine if there is piped input: %+v", err)
		return true
	}
	// verbosity should consider if there is piped input (in which case we should not show the ETUI)
	return appConfig.CliOptions.Verbosity > 0 || isPipedInput
}

//nolint:funlen
func startWorker(userInput string, failOnSeverity *vulnerability.Severity) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		presenterConfig, err := presenter.ValidatedConfig(appConfig.Output, appConfig.OutputTemplateFile, appConfig.ShowSuppressed)
		if err != nil {
			errs <- err
			return
		}

		checkForAppUpdate()

		var str *store.Store
		var status *db.Status
		var dbCloser *db.Closer
		var packages []pkg.Package
		var sbom *sbom.SBOM
		var pkgContext pkg.Context
		var wg = &sync.WaitGroup{}
		var loadedDB, gatheredPackages bool

		wg.Add(2)

		go func() {
			defer wg.Done()
			log.Debug("loading DB")
			str, status, dbCloser, err = grype.LoadVulnerabilityDB(appConfig.DB.ToCuratorConfig(), appConfig.DB.AutoUpdate)
			if err = validateDBLoad(err, status); err != nil {
				errs <- err
				return
			}
			loadedDB = true
		}()

		go func() {
			defer wg.Done()
			log.Debugf("gathering packages")
			// packages are grype.Pacakge, not syft.Package
			// the SBOM is returned for downstream formatting concerns
			// grype uses the SBOM in combination with syft formatters to produce cycloneDX
			// with vulnerability information appended
			packages, pkgContext, sbom, err = pkg.Provide(userInput, getProviderConfig())
			if err != nil {
				errs <- fmt.Errorf("failed to catalog: %w", err)
				return
			}
			gatheredPackages = true
		}()

		wg.Wait()
		if !loadedDB || !gatheredPackages {
			return
		}

		if dbCloser != nil {
			defer dbCloser.Close()
		}

		if appConfig.OnlyFixed {
			appConfig.Ignore = append(appConfig.Ignore, ignoreNonFixedMatches...)
		}

		if appConfig.OnlyNotFixed {
			appConfig.Ignore = append(appConfig.Ignore, ignoreFixedMatches...)
		}

		applyDistroHint(packages, &pkgContext, appConfig)

		vulnMatcher := grype.VulnerabilityMatcher{
			Store:          *str,
			IgnoreRules:    appConfig.Ignore,
			NormalizeByCVE: appConfig.ByCVE,
			FailSeverity:   failOnSeverity,
			Matchers:       getMatchers(),
		}

		remainingMatches, ignoredMatches, err := vulnMatcher.FindMatches(packages, pkgContext)
		if err != nil {
			errs <- err
			if !errors.Is(err, grypeerr.ErrAboveSeverityThreshold) {
				return
			}
		}

		pb := models.PresenterConfig{
			Matches:          *remainingMatches,
			IgnoredMatches:   ignoredMatches,
			Packages:         packages,
			Context:          pkgContext,
			MetadataProvider: str,
			SBOM:             sbom,
			AppConfig:        appConfig,
			DBStatus:         status,
		}

		bus.Publish(partybus.Event{
			Type:  event.VulnerabilityScanningFinished,
			Value: presenter.GetPresenter(presenterConfig, pb),
		})
	}()
	return errs
}

func applyDistroHint(pkgs []pkg.Package, context *pkg.Context, appConfig *config.Application) {
	if appConfig.Distro != "" {
		log.Infof("using distro: %s", appConfig.Distro)

		split := strings.Split(appConfig.Distro, ":")
		d := split[0]
		v := ""
		if len(split) > 1 {
			v = split[1]
		}
		context.Distro = &linux.Release{
			PrettyName: d,
			Name:       d,
			ID:         d,
			IDLike: []string{
				d,
			},
			Version:   v,
			VersionID: v,
		}
	}

	hasOSPackage := false
	for _, p := range pkgs {
		switch p.Type {
		case syftPkg.AlpmPkg, syftPkg.DebPkg, syftPkg.RpmPkg, syftPkg.KbPkg:
			hasOSPackage = true
		}
	}

	if context.Distro == nil && hasOSPackage {
		log.Warnf("Unable to determine the OS distribution. This may result in missing vulnerabilities. " +
			"You may specify a distro using: --distro <distro>:<version>")
	}
}

func checkForAppUpdate() {
	if !appConfig.CheckForAppUpdate {
		return
	}

	isAvailable, newVersion, err := version.IsUpdateAvailable()
	if err != nil {
		log.Errorf(err.Error())
	}
	if isAvailable {
		log.Infof("new version of %s is available: %s (currently running: %s)", internal.ApplicationName, newVersion, version.FromBuild().Version)

		bus.Publish(partybus.Event{
			Type:  event.AppUpdateAvailable,
			Value: newVersion,
		})
	} else {
		log.Debugf("no new %s update available", internal.ApplicationName)
	}
}

func getMatchers() []matcher.Matcher {
	return matcher.NewDefaultMatchers(
		matcher.Config{
			Java: java.MatcherConfig{
				ExternalSearchConfig: appConfig.ExternalSources.ToJavaMatcherConfig(),
				UseCPEs:              appConfig.Match.Java.UseCPEs,
			},
			Ruby:       ruby.MatcherConfig(appConfig.Match.Ruby),
			Python:     python.MatcherConfig(appConfig.Match.Python),
			Dotnet:     dotnet.MatcherConfig(appConfig.Match.Dotnet),
			Javascript: javascript.MatcherConfig(appConfig.Match.Javascript),
			Golang:     golang.MatcherConfig(appConfig.Match.Golang),
			Stock:      stock.MatcherConfig(appConfig.Match.Stock),
		},
	)
}

func getProviderConfig() pkg.ProviderConfig {
	return pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions:        appConfig.Registry.ToOptions(),
			Exclusions:             appConfig.Exclusions,
			CatalogingOptions:      appConfig.Search.ToConfig(),
			Platform:               appConfig.Platform,
			Name:                   appConfig.Name,
			DefaultImagePullSource: appConfig.DefaultImagePullSource,
		},
		SynthesisConfig: pkg.SynthesisConfig{
			GenerateMissingCPEs: appConfig.GenerateMissingCPEs,
		},
	}
}

func validateDBLoad(loadErr error, status *db.Status) error {
	if loadErr != nil {
		return fmt.Errorf("failed to load vulnerability db: %w", loadErr)
	}
	if status == nil {
		return fmt.Errorf("unable to determine the status of the vulnerability db")
	}
	if status.Err != nil {
		return fmt.Errorf("db could not be loaded: %w", status.Err)
	}
	return nil
}

func validateRootArgs(cmd *cobra.Command, args []string) error {
	isPipedInput, err := internal.IsPipedInput()
	if err != nil {
		log.Warnf("unable to determine if there is piped input: %+v", err)
		isPipedInput = false
	}

	if len(args) == 0 && !isPipedInput {
		// in the case that no arguments are given and there is no piped input we want to show the help text and return with a non-0 return code.
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf("an image/directory argument is required")
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}
