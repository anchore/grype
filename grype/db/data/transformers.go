package data

import (
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
)

// Transformers are functions that know how ta take individual data shapes defined in the unmarshal package and
// reshape the data into data.Entry objects that are writable by a data.Writer. Transformers are dependency-injected
// into commonly-shared data.Processors in the individual process.v* packages.

// all v1 transformers (schema v1 - v5)

type GitHubTransformer func(entry unmarshal.GitHubAdvisory) ([]Entry, error)
type MSRCTransformer func(entry unmarshal.MSRCVulnerability) ([]Entry, error)
type NVDTransformer func(entry unmarshal.NVDVulnerability) ([]Entry, error)
type OSTransformer func(entry unmarshal.OSVulnerability) ([]Entry, error)
type MatchExclusionTransformer func(entry unmarshal.MatchExclusion) ([]Entry, error)

// all v2 transformers (schema v6+)

type GitHubTransformerV2 func(entry unmarshal.GitHubAdvisory, state provider.State) ([]Entry, error)
type MSRCTransformerV2 func(entry unmarshal.MSRCVulnerability, state provider.State) ([]Entry, error)
type NVDTransformerV2 func(entry unmarshal.NVDVulnerability, state provider.State) ([]Entry, error)
type OSTransformerV2 func(entry unmarshal.OSVulnerability, state provider.State) ([]Entry, error)
type MatchExclusionTransformerV2 func(entry unmarshal.MatchExclusion, state provider.State) ([]Entry, error)

type KnownExploitedVulnerabilityTransformerV2 func(entry unmarshal.KnownExploitedVulnerability, state provider.State) ([]Entry, error)
type EPSSTransformerV2 func(entry unmarshal.EPSS, state provider.State) ([]Entry, error)
type OSVTransformerV2 func(entry unmarshal.OSVVulnerability, state provider.State) ([]Entry, error)
type OpenVEXTransformerV2 func(entry unmarshal.OpenVEXVulnerability, state provider.State) ([]Entry, error)
type AnnotatedOpenVEXTransformerV2 func(entry unmarshal.AnnotatedOpenVEXVulnerability, state provider.State) ([]Entry, error)
