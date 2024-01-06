package match

import "github.com/anchore/grype/grype/pkg"

type Processor interface {
	ProcessMatches(pkg.Context, Matches, []IgnoredMatch) (Matches, []IgnoredMatch, error)
}
