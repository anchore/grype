package result

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
)

// ToMatches takes results from a Set and converts them to concrete match.Match results
func ToMatches(s Set, matcher match.MatcherType, p pkg.Package) []match.Match {
	var out []match.Match
	for _, results := range s {
		if len(results) == 0 {
			continue
		}
		for _, v := range results {
			out = append(out, match.Match{
				Vulnerability: v.Vulnerability,
				Package:       p,
				Details:       detailProvider(matcher, p, v.Criteria, v.Vulnerability),
			})
		}
	}
	return out
}
