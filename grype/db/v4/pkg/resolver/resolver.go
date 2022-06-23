package resolver

import (
	grypePkg "github.com/anchore/grype/grype/pkg"
)

type Resolver interface {
	Normalize(string) string
	Resolve(p grypePkg.Package) []string
}
