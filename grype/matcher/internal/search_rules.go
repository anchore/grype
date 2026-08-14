package internal

import (
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// IncludeBaseDistro reports whether a match for the given package should consider its own distro's
// data and the ecosystem's upstream data (e.g. the NVD/CPE search apk falls back to for
// disclosures), or whether the provider's search rules already route it to data that is the
// complete picture for it — both disclosures and fixes, as rapidfort-alpine's curated feed is.
// Providers that expose no search rules include everything, which is the historical behavior.
//
// The distro search itself is rewritten by the provider (see v6.applySearchRules), so this exists
// for the searches a matcher makes on its own and cannot be rewritten for it. Rules that disagree
// resolve to true: one rule reporting its records as fixes-only is reason enough to keep searching,
// which makes the fold independent of rule order.
func IncludeBaseDistro(provider vulnerability.Provider, p pkg.Package) bool {
	rp, ok := provider.(vulnerability.SearchRuleProvider)
	if !ok {
		return true
	}

	include := true
	for _, r := range rp.SearchRules(p) {
		if r.IncludeBaseDistro == nil {
			continue // no preference; another rule may still have one
		}
		if *r.IncludeBaseDistro {
			return true
		}
		include = false
	}
	return include
}
