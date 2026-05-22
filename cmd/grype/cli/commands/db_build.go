package commands

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/db/build/providers"
	"github.com/anchore/grype/grype/db/build/providers/vunnel"
	"github.com/anchore/grype/grype/db/build/pull"
	dbprovider "github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

const (
	skipPhasePull     = "pull"
	skipPhaseValidate = "validate"
	skipPhaseWrite    = "write"
	skipPhasePackage  = "package"
)

var allSkipPhases = []string{skipPhasePull, skipPhaseValidate, skipPhaseWrite, skipPhasePackage}

// dbBuildConfigWrapper nests the DatabaseBuild options under `db.build:` in
// the application YAML config so the schema remains coherent next to the
// existing `db:` settings used by other db commands. The command flags are
// still registered directly on DatabaseBuild via its AddFlags method.
type dbBuildConfigWrapper struct {
	DB dbBuildConfigDBSection `yaml:"db" json:"db" mapstructure:"db"`
}

type dbBuildConfigDBSection struct {
	Build *options.DatabaseBuild `yaml:"build" json:"build" mapstructure:"build"`
}

func DBBuild(app clio.Application) *cobra.Command {
	opts := options.DefaultDatabaseBuild()

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build a vulnerability database from upstream vulnerability data",
		Long: `Build a vulnerability database by running the full pull -> write -> package
pipeline. Use --skip to omit any combination of phases (pull, validate, write,
package); for example:

  grype db build --skip pull,package   # build a DB from existing provider data
  grype db build --skip pull,write     # only package an already-built DB`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return disableUI(app)(cmd, args)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBBuild(opts)
		},
	}

	return app.SetupCommand(cmd, &dbBuildConfigWrapper{DB: dbBuildConfigDBSection{Build: opts}})
}

func runDBBuild(opts *options.DatabaseBuild) error {
	skip, err := parseSkipPhases(opts.Skip)
	if err != nil {
		return err
	}

	if err := validateCPEParts(opts.IncludeCPEParts); err != nil {
		return err
	}

	if opts.ArchiveExtension != "" && !strset.New("tar.gz", "tar.zst").Has(opts.ArchiveExtension) {
		return fmt.Errorf("archive-extension must be 'tar.gz' or 'tar.zst'")
	}

	needProviders := !skip.Has(skipPhasePull) || !skip.Has(skipPhaseWrite)

	var pvdrs dbprovider.Providers
	if needProviders {
		pvdrs, err = buildProviders(opts)
		if err != nil {
			return err
		}
	}

	if !skip.Has(skipPhasePull) {
		if err := runPullPhase(opts, pvdrs); err != nil {
			return fmt.Errorf("pull phase failed: %w", err)
		}
	} else {
		log.Info("skipping pull phase")
	}

	if !skip.Has(skipPhaseWrite) {
		if err := runWritePhase(opts, pvdrs, skip.Has(skipPhaseValidate)); err != nil {
			return fmt.Errorf("write phase failed: %w", err)
		}
	} else {
		log.Info("skipping write phase")
	}

	if !skip.Has(skipPhasePackage) {
		if err := runPackagePhase(opts); err != nil {
			return fmt.Errorf("package phase failed: %w", err)
		}
	} else {
		log.Info("skipping package phase")
	}

	return nil
}

func parseSkipPhases(raw []string) (*strset.Set, error) {
	set := strset.New()
	for _, entry := range raw {
		for _, p := range strings.Split(entry, ",") {
			p = strings.TrimSpace(strings.ToLower(p))
			if p == "" {
				continue
			}
			if !strset.New(allSkipPhases...).Has(p) {
				return nil, fmt.Errorf("invalid --skip phase %q (allowed: %s)", p, strings.Join(allSkipPhases, ", "))
			}
			set.Add(p)
		}
	}
	return set, nil
}

func validateCPEParts(parts []string) error {
	if len(parts) == 0 {
		return errors.New("no CPE parts provided")
	}
	validParts := strset.New("a", "o", "h")
	for _, part := range parts {
		if !validParts.Has(part) {
			return fmt.Errorf("invalid CPE part: %s", part)
		}
	}
	return nil
}

func buildProviders(opts *options.DatabaseBuild) (dbprovider.Providers, error) {
	vCfg := vunnel.Config{
		Config:           opts.Provider.Vunnel.Config,
		Executor:         opts.Provider.Vunnel.Executor,
		DockerImage:      opts.Provider.Vunnel.DockerImage,
		DockerTag:        opts.Provider.Vunnel.DockerTag,
		GenerateConfigs:  opts.Provider.Vunnel.GenerateConfigs,
		ExcludeProviders: opts.Provider.Vunnel.ExcludeProviders,
		Env:              map[string]string(opts.Provider.Vunnel.Env),
	}

	cfgs := append([]pull.ProviderRunConfig(nil), opts.Provider.Configs...)

	// If the user passed -p but didn't supply explicit configs and didn't ask
	// to enumerate via `vunnel list` (-g), treat each -p value as a vunnel
	// provider config. This lets `-p alpine -p alma` work on its own when the
	// provider data already exists on disk under provider.root.
	if len(cfgs) == 0 && !vCfg.GenerateConfigs && len(opts.Provider.IncludeFilter) > 0 {
		for _, name := range opts.Provider.IncludeFilter {
			cfgs = append(cfgs, pull.ProviderRunConfig{
				Identifier: dbprovider.Identifier{
					Name: name,
					Kind: vunnel.Kind,
				},
			})
		}
		log.WithFields("providers", opts.Provider.IncludeFilter).Debug("synthesized vunnel provider configs from --provider-name")
	}

	pvdrs, err := providers.New(opts.Provider.Root, vCfg, cfgs...)
	if err != nil {
		if errors.Is(err, providers.ErrNoProviders) {
			log.Error("configure a provider via the application config, pass -p <name> for each provider, or use -g to enumerate them via vunnel list")
		}
		return nil, fmt.Errorf("unable to create providers: %w", err)
	}

	// Only run the post-filter when configs or -g produced the provider set;
	// when -p synthesized them above, the filter is implicit.
	hadExplicitSources := vCfg.GenerateConfigs || len(opts.Provider.Configs) > 0
	if hadExplicitSources && len(opts.Provider.IncludeFilter) > 0 {
		log.WithFields("keep-only", opts.Provider.IncludeFilter).Debug("filtering providers by name")
		pvdrs = pvdrs.Filter(opts.Provider.IncludeFilter...)
	}

	return pvdrs, nil
}

func runPullPhase(opts *options.DatabaseBuild, pvdrs dbprovider.Providers) error {
	return pull.Pull(pull.Config{
		Parallelism: opts.Pull.Parallelism,
		Collection: dbprovider.Collection{
			Root:      opts.Provider.Root,
			Providers: pvdrs,
		},
	})
}

func runWritePhase(opts *options.DatabaseBuild, pvdrs dbprovider.Providers, skipValidation bool) error {
	if _, err := os.Stat(opts.Dir); os.IsNotExist(err) {
		if err := os.MkdirAll(opts.Dir, 0755); err != nil {
			return fmt.Errorf("unable to make db build dir: %w", err)
		}
	}

	states, err := providerStates(skipValidation, pvdrs)
	if err != nil {
		return fmt.Errorf("unable to get provider states: %w", err)
	}

	earliest, err := dbprovider.States(states).EarliestTimestamp()
	if err != nil {
		return fmt.Errorf("unable to get earliest timestamp: %w", err)
	}

	return db.Build(db.BuildConfig{
		SchemaVersion:        opts.SchemaVersion,
		Directory:            opts.Dir,
		States:               states,
		Timestamp:            earliest,
		IncludeCPEParts:      opts.IncludeCPEParts,
		InferNVDFixVersions:  opts.InferNVDFixVersions,
		Hydrate:              opts.Hydrate,
		FailOnMissingFixDate: opts.FailOnMissingFixDate,
		BatchSize:            opts.BatchSize,
	})
}

func runPackagePhase(opts *options.DatabaseBuild) error {
	// v5 DB writing (and its corresponding listing.json) is no longer supported via this command;
	// publish-base-url is intentionally omitted.
	return db.Package(opts.Dir, "", opts.ArchiveExtension, map[string]string(opts.CompressorCommands))
}

func providerStates(skipValidation bool, providers []dbprovider.Reader) ([]dbprovider.State, error) {
	var states []dbprovider.State
	log.Debug("reading all provider state")

	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers configured")
	}

	for _, p := range providers {
		log.WithFields("provider", p.ID().Name).Debug("reading state")

		sd, err := p.State()
		if err != nil {
			return nil, fmt.Errorf("unable to read provider state: %w", err)
		}

		if !skipValidation {
			log.WithFields("provider", p.ID().Name).Trace("validating state")
			if err := sd.Verify(); err != nil {
				return nil, fmt.Errorf("invalid provider state: %w", err)
			}
		}
		states = append(states, *sd)
	}
	if !skipValidation {
		log.Debugf("state validated for all providers")
	}
	return states, nil
}
