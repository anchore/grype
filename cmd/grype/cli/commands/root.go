package commands

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	grypeDb "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/event/parsers"
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
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/format"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/stringutil"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func Root(app clio.Application) *cobra.Command {
	opts := options.DefaultGrype(app.ID())

	return app.SetupRootCommand(&cobra.Command{
		Use:   fmt.Sprintf("%s [IMAGE]", app.ID().Name),
		Short: "A vulnerability scanner for container images, filesystems, and SBOMs",
		Long: stringutil.Tprintf(`A vulnerability scanner for container images, filesystems, and SBOMs.

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
			"appName": app.ID().Name,
		}),
		Args:          validateRootArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			userInput := ""
			if len(args) > 0 {
				userInput = args[0]
			}
			return runGrype(app, opts, userInput)
		},
		ValidArgsFunction: dockerImageValidArgsFunction,
	}, opts)
}

var ignoreNonFixedMatches = []match.IgnoreRule{
	{FixState: string(grypeDb.NotFixedState)},
	{FixState: string(grypeDb.WontFixState)},
	{FixState: string(grypeDb.UnknownFixState)},
}

var ignoreFixedMatches = []match.IgnoreRule{
	{FixState: string(grypeDb.FixedState)},
}

var ignoreVEXFixedNotAffected = []match.IgnoreRule{
	{VexStatus: string(vex.StatusNotAffected)},
	{VexStatus: string(vex.StatusFixed)},
}

//nolint:funlen
func runGrype(app clio.Application, opts *options.Grype, userInput string) (errs error) {
	writer, err := format.MakeScanResultWriter(opts.Outputs, opts.File, format.PresentationConfig{
		TemplateFilePath: opts.OutputTemplateFile,
		ShowSuppressed:   opts.ShowSuppressed,
	})
	if err != nil {
		return err
	}

	var str *store.Store
	var status *db.Status
	var dbCloser *db.Closer
	var packages []pkg.Package
	var s *sbom.SBOM
	var pkgContext pkg.Context

	err = parallel(
		func() error {
			checkForAppUpdate(app.ID(), opts)
			return nil
		},
		func() (err error) {
			log.Debug("loading DB")
			str, status, dbCloser, err = grype.LoadVulnerabilityDB(opts.DB.ToCuratorConfig(), opts.DB.AutoUpdate)
			return validateDBLoad(err, status)
		},
		func() (err error) {
			log.Debugf("gathering packages")
			// packages are grype.Package, not syft.Package
			// the SBOM is returned for downstream formatting concerns
			// grype uses the SBOM in combination with syft formatters to produce cycloneDX
			// with vulnerability information appended
			packages, pkgContext, s, err = pkg.Provide(userInput, getProviderConfig(opts))
			if err != nil {
				return fmt.Errorf("failed to catalog: %w", err)
			}
			return nil
		},
	)

	if err != nil {
		return err
	}

	if dbCloser != nil {
		defer dbCloser.Close()
	}

	if opts.OnlyFixed {
		opts.Ignore = append(opts.Ignore, ignoreNonFixedMatches...)
	}

	if opts.OnlyNotFixed {
		opts.Ignore = append(opts.Ignore, ignoreFixedMatches...)
	}

	if err = applyVexRules(opts); err != nil {
		return fmt.Errorf("applying vex rules: %w", err)
	}

	applyDistroHint(packages, &pkgContext, opts)

	vulnMatcher := grype.VulnerabilityMatcher{
		Store:          *str,
		IgnoreRules:    opts.Ignore,
		NormalizeByCVE: opts.ByCVE,
		FailSeverity:   opts.FailOnServerity(),
		Matchers:       getMatchers(opts),
		VexProcessor: vex.NewProcessor(vex.ProcessorOptions{
			Documents:   opts.VexDocuments,
			IgnoreRules: opts.Ignore,
		}),
	}

	remainingMatches, ignoredMatches, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		if !errors.Is(err, grypeerr.ErrAboveSeverityThreshold) {
			return err
		}
		errs = appendErrors(errs, err)
	}

	if err = writer.Write(models.PresenterConfig{
		ID:               app.ID(),
		Matches:          *remainingMatches,
		IgnoredMatches:   ignoredMatches,
		Packages:         packages,
		Context:          pkgContext,
		MetadataProvider: str,
		SBOM:             s,
		AppConfig:        opts,
		DBStatus:         status,
	}); err != nil {
		errs = appendErrors(errs, err)
	}

	return errs
}

func applyDistroHint(pkgs []pkg.Package, context *pkg.Context, opts *options.Grype) {
	if opts.Distro != "" {
		log.Infof("using distro: %s", opts.Distro)

		split := strings.Split(opts.Distro, ":")
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

func checkForAppUpdate(id clio.Identification, opts *options.Grype) {
	if !opts.CheckForAppUpdate {
		return
	}

	version := id.Version
	isAvailable, newVersion, err := isUpdateAvailable(version)
	if err != nil {
		log.Errorf(err.Error())
	}
	if isAvailable {
		log.Infof("new version of %s is available: %s (currently running: %s)", id.Name, newVersion, version)

		bus.Publish(partybus.Event{
			Type: event.CLIAppUpdateAvailable,
			Value: parsers.UpdateCheck{
				New:     newVersion,
				Current: id.Version,
			},
		})
	} else {
		log.Debugf("no new %s update available", id.Name)
	}
}

func getMatchers(opts *options.Grype) []matcher.Matcher {
	return matcher.NewDefaultMatchers(
		matcher.Config{
			Java: java.MatcherConfig{
				ExternalSearchConfig: opts.ExternalSources.ToJavaMatcherConfig(),
				UseCPEs:              opts.Match.Java.UseCPEs,
			},
			Ruby:       ruby.MatcherConfig(opts.Match.Ruby),
			Python:     python.MatcherConfig(opts.Match.Python),
			Dotnet:     dotnet.MatcherConfig(opts.Match.Dotnet),
			Javascript: javascript.MatcherConfig(opts.Match.Javascript),
			Golang:     golang.MatcherConfig(opts.Match.Golang),
			Stock:      stock.MatcherConfig(opts.Match.Stock),
		},
	)
}

func getProviderConfig(opts *options.Grype) pkg.ProviderConfig {
	return pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions:        opts.Registry.ToOptions(),
			Exclusions:             opts.Exclusions,
			CatalogingOptions:      opts.Search.ToConfig(),
			Platform:               opts.Platform,
			Name:                   opts.Name,
			DefaultImagePullSource: opts.DefaultImagePullSource,
		},
		SynthesisConfig: pkg.SynthesisConfig{
			GenerateMissingCPEs: opts.GenerateMissingCPEs,
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
	isStdinPipeOrRedirect, err := internal.IsStdinPipeOrRedirect()
	if err != nil {
		log.Warnf("unable to determine if there is piped input: %+v", err)
		isStdinPipeOrRedirect = false
	}

	if len(args) == 0 && !isStdinPipeOrRedirect {
		// in the case that no arguments are given and there is no piped input we want to show the help text and return with a non-0 return code.
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf("an image/directory argument is required")
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}

func applyVexRules(opts *options.Grype) error {
	if len(opts.Ignore) == 0 && len(opts.VexDocuments) > 0 {
		opts.Ignore = append(opts.Ignore, ignoreVEXFixedNotAffected...)
	}

	for _, vexStatus := range opts.VexAdd {
		switch vexStatus {
		case string(vex.StatusAffected):
			opts.Ignore = append(
				opts.Ignore, match.IgnoreRule{VexStatus: string(vex.StatusAffected)},
			)
		case string(vex.StatusUnderInvestigation):
			opts.Ignore = append(
				opts.Ignore, match.IgnoreRule{VexStatus: string(vex.StatusUnderInvestigation)},
			)
		default:
			return fmt.Errorf("invalid VEX status in vex-add setting: %s", vexStatus)
		}
	}

	return nil
}
