package mock

import (
	"errors"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// MatchFunc is a function that takes a vulnerability provider and a package,
// and returns matches, ignored matches, and an error.
type MatchFunc func(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoredMatch, error)

// Matcher is a mock implementation of the match.Matcher interface. This is
// intended for testing purposes only.
type Matcher struct {
	typ       syftPkg.Type
	matchFunc MatchFunc
}

// New creates a new mock Matcher with the given type and match function.
func New(typ syftPkg.Type, matchFunc MatchFunc) *Matcher {
	return &Matcher{
		typ:       typ,
		matchFunc: matchFunc,
	}
}

func (m Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{m.typ}
}

func (m Matcher) Type() match.MatcherType {
	return "MOCK"
}

func (m Matcher) Match(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoredMatch, error) {
	if m.matchFunc != nil {
		return m.matchFunc(vp, p)
	}

	return nil, nil, errors.New("no match function provided")
}
