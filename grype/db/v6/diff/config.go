package diff

import "github.com/anchore/grype/grype/db/v6/installation"

func DefaultConfig() Config {
	return Config{
		EPSSThreshold: 0.1,
		Include: Includes{
			Packages: true,
			Vulns:    true,
			KEV:      true,
		},
	}
}

type Includes struct {
	Packages bool
	Vulns    bool
	EPSS     bool
	KEV      bool
}

type Config struct {
	installation.Config
	Include       Includes
	Debug         bool
	EPSSThreshold float64
	OldDB         string
	NewDB         string
}

func (c Config) IncludePackages() bool {
	if allUnset(c.Include) {
		return true
	}
	return c.Include.Packages
}

func (c Config) IncludeVulns() bool {
	if allUnset(c.Include) {
		return true
	}
	return c.Include.Vulns
}

func (c Config) IncludeEPSS() bool {
	return c.Include.EPSS
}

func (c Config) IncludeKEV() bool {
	if allUnset(c.Include) {
		return true
	}
	return c.Include.KEV
}

func allUnset(include Includes) bool {
	return !include.Packages && !include.Vulns
}
