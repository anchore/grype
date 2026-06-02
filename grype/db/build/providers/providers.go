package providers

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"

	"github.com/anchore/grype/grype/db/build/providers/external"
	"github.com/anchore/grype/grype/db/build/providers/vunnel"
	"github.com/anchore/grype/grype/db/build/pull"
	"github.com/anchore/grype/grype/db/provider"
)

var ErrNoProviders = fmt.Errorf("no providers configured")

func New(root string, vCfg vunnel.Config, cfgs ...pull.ProviderRunConfig) (provider.Providers, error) {
	var providers []provider.Reader
	var eolProviders []provider.Reader

	if vCfg.GenerateConfigs {
		generatedCfgs, err := vunnel.GenerateConfigs(root, vCfg)
		if err != nil {
			return nil, fmt.Errorf("unable to generate vunnel providers: %w", err)
		}
		cfgs = append(cfgs, generatedCfgs...)
	}

	if len(cfgs) == 0 {
		return nil, ErrNoProviders
	}

	for _, cfg := range cfgs {
		p, err := newProvider(root, vCfg, cfg)
		if err != nil {
			return nil, err
		}
		switch p.ID().Name {
		case "nvd":
			// it is important that NVD is processed first since other providers depend on the severity information from these records
			providers = append([]provider.Reader{p}, providers...)
		case "eol":
			// EOL provider must run last since it needs OperatingSystem records to exist (created by other providers)
			eolProviders = append(eolProviders, p)
		default:
			providers = append(providers, p)
		}
	}

	// append EOL providers at the end
	providers = append(providers, eolProviders...)

	return providers, nil
}

func newProvider(root string, vCfg vunnel.Config, cfg pull.ProviderRunConfig) (provider.Reader, error) {
	switch cfg.Kind {
	case vunnel.Kind, "": // note: this is the default
		return vunnel.NewProvider(root, cfg.Identifier, vCfg), nil
	case external.Kind:
		var c external.Config
		if err := mapstructure.Decode(cfg.Config, &c); err != nil {
			return nil, fmt.Errorf("failed to decode external provider config: %w", err)
		}
		return external.NewProvider(root, cfg.Identifier, c), nil
	case "internal": // reserved, not implemented (golang vulnerability data providers in-repo)
		return nil, fmt.Errorf("internal providers not yet implemented")
	default:
		return nil, fmt.Errorf("unknown provider kind %q", cfg.Kind)
	}
}
