package golang

import (
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	UseCPEs                                bool
	AlwaysUseCPEForStdlib                  bool
	AllowMainModulePseudoVersionComparison bool
}

func NewGolangMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.GoModulePkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.GoModuleMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	matches := make([]match.Match, 0)

	mainModule := ""
	if m, ok := p.Metadata.(pkg.GolangBinMetadata); ok {
		mainModule = m.MainModule
	}

	// Golang currently does not have a standard way of incorporating the main
	// module's version into the compiled binary:
	// https://github.com/golang/go/issues/50603.
	//
	// Syft has some fallback mechanisms to come up with a more sane version value
	// depending on the scenario. But if none of these apply, the Go-set value of
	// "(devel)" is used, which is altogether unhelpful for vulnerability matching.
	var isNotCorrected bool
	if m.cfg.AllowMainModulePseudoVersionComparison {
		isNotCorrected = strings.HasPrefix(p.Version, "(devel)")
	} else {
		// when AllowPseudoVersionComparison is false
		isNotCorrected = strings.HasPrefix(p.Version, "v0.0.0-") || strings.HasPrefix(p.Version, "(devel)")
	}
	if p.Name == mainModule && isNotCorrected {
		return matches, nil, nil
	}

	matches, ignored, err := internal.MatchPackageByEcosystemAndCPEs(store, p, m.Type(), searchByCPE(p.Name, m.cfg))
	if err != nil {
		return nil, nil, err
	}

	// Go advisories are routinely filed against an import path inside a larger module
	// (e.g. "golang.org/x/crypto/ssh" inside "golang.org/x/crypto"). Go binaries only
	// retain module-granularity build info via debug/buildinfo, so syft cannot emit the
	// import-path entries the advisory expects. Without a fallback the exact-name lookup
	// silently misses these. We supplement the exact match with a prefix-search keyed on
	// p.Name + "/", so an SBOM module also surfaces advisories pinned to import paths
	// strictly under it. The path-segment boundary in the prefix prevents a sibling
	// module with a coincident name prefix (e.g. "golang.org/x/cryptographer") from
	// matching "golang.org/x/crypto" inputs.
	if shouldSearchSubPathAdvisories(p) {
		subMatches, subIgnored, err := matchSubPathAdvisories(store, p, m.Type())
		if err != nil {
			return nil, nil, err
		}
		matches = append(matches, subMatches...)
		ignored = append(ignored, subIgnored...)
	}

	return matches, ignored, nil
}

// shouldSearchSubPathAdvisories reports whether the package name resembles a Go module
// path that may host advisories at sub-import-path granularity. We require the name to
// contain at least one "/" so e.g. the synthetic "stdlib" entry, single-segment names,
// or empty names don't fan out across the entire Go advisory corpus.
func shouldSearchSubPathAdvisories(p pkg.Package) bool {
	if p.Type != syftPkg.GoModulePkg {
		return false
	}
	return strings.Contains(p.Name, "/")
}

// matchSubPathAdvisories looks up vulnerabilities pinned at an import-path strictly under
// p.Name and returns matches against the SBOM package's version. The normal ecosystem
// pipeline (version constraints, unaffected handling, qualified-package filters) is reused
// via internal.MatchPackageByEcosystemPackageNamePrefix. CPEs are intentionally not
// re-queried here; the exact-name path above already covered them for p.Name.
func matchSubPathAdvisories(store vulnerability.Provider, p pkg.Package, matcherType match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	return internal.MatchPackageByEcosystemPackageNamePrefix(store, p, p.Name, matcherType)
}

func searchByCPE(name string, cfg MatcherConfig) bool {
	if cfg.UseCPEs {
		return true
	}

	return cfg.AlwaysUseCPEForStdlib && (name == "stdlib")
}
