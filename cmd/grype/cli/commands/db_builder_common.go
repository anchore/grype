package commands

import (
	"errors"
	"fmt"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db/build/providers"
	"github.com/anchore/grype/grype/db/build/providers/vunnel"
	"github.com/anchore/grype/grype/db/build/pull"
	dbprovider "github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

// dbBuilderConfigWrapper places the DatabaseBuild options under a top-level
// `db-builder:` key in the application YAML, parallel to the existing `db:`
// section used by end-user `grype db ...` commands. All three db-builder
// subcommands share the same configuration view.
type dbBuilderConfigWrapper struct {
	DBBuilder *options.DatabaseBuild `yaml:"db-builder" json:"db-builder" mapstructure:"db-builder"`
}

// buildProviders constructs the provider collection used by both the pull and
// the write subcommands. The provider set comes from one of (in order):
//   - explicit provider configs in the YAML
//   - -g (generate via `vunnel list`)
//   - -p <name> (synthesized vunnel provider configs)
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
