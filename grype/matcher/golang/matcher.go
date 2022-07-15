package golang

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"strings"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.GoModulePkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.GoModuleMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	matches := make([]match.Match, 0)
	metadata := pkg.GolangBinMetadata{}
	if p.Metadata != nil {
		metadata = p.Metadata.(pkg.GolangBinMetadata)
	}

	// Golang currently does not have a standard way of incorporating the vcs version
	// into the compiled binary: https://github.com/golang/go/issues/50603
	// current version information for the main module is incomplete leading to multiple FP
	// TODO: remove this exclusion when vcs information is included in future go version
	if p.Name == metadata.MainModule && strings.HasPrefix(p.Version, "v0.0.0-") {
		return search.ByCriteria(store, d, p, m.Type(), search.CommonCriteria...)
	}

	return matches, nil
}
