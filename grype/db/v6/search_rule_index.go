package v6

import (
	"slices"
	"strings"

	"github.com/anchore/grype/grype/pkg"
)

// searchRuleIndex is the compiled, queryable form of the search rule set. Rule selection is dominated
// by the two predicates that are exact case-insensitive compares rather than patterns —
// MatchDistroName and MatchEcosystem — so rules are filed by those and a query only ever evaluates the
// rules that could possibly match it. The regex predicates then decide, exactly as they would in a
// linear scan over the whole set: the index only narrows the candidate set, so it cannot change which
// rules apply.
type searchRuleIndex struct {
	// rules is the compiled set in the order it was read; the buckets below hold the same pointers,
	// so a rule is stored once however many ways it can be reached
	rules []*compiledSearchRule

	// byDistroName files rules with a MatchDistroName, keyed by its lowercased value. Such a rule can
	// only match a query carrying that distro, so a query's OS specifiers select its buckets directly.
	byDistroName map[string][]*compiledSearchRule

	// byEcosystem files rules with no distro name but a MatchEcosystem, which requires the query to
	// carry an ecosystem and is therefore unreachable from distro queries.
	byEcosystem map[string][]*compiledSearchRule

	// unscoped holds rules with neither exact predicate — candidates for every query, and the one
	// shape the index cannot narrow. KnownSearchRules has none.
	unscoped []*compiledSearchRule
}

func newSearchRuleIndex(rows []SearchRule) *searchRuleIndex {
	idx := &searchRuleIndex{
		rules:        compileSearchRules(rows),
		byDistroName: map[string][]*compiledSearchRule{},
		byEcosystem:  map[string][]*compiledSearchRule{},
	}

	for i, r := range idx.rules {
		r.ord = i

		// a rule is filed under exactly one key, so buckets are disjoint and gathering candidates from
		// several of them needs no deduplication. Distro name wins over ecosystem: a rule naming a
		// distro requires that distro whatever its ecosystem predicate says.
		switch {
		case r.row.MatchDistroName != "":
			key := strings.ToLower(r.row.MatchDistroName)
			idx.byDistroName[key] = append(idx.byDistroName[key], r)
		case r.row.MatchEcosystem != "":
			key := strings.ToLower(r.row.MatchEcosystem)
			idx.byEcosystem[key] = append(idx.byEcosystem[key], r)
		default:
			idx.unscoped = append(idx.unscoped, r)
		}
	}

	return idx
}

// candidates appends the rules that could match the package to dst, in the order the rules were read.
// Restoring that order is what makes resolution byte-identical to a linear scan over the whole set,
// which is the entire safety argument for indexing: the index only narrows what is evaluated.
func (idx *searchRuleIndex) candidates(p pkg.Package, dst []*compiledSearchRule) []*compiledSearchRule {
	if idx == nil || len(idx.rules) == 0 {
		return dst
	}

	dst = append(dst, idx.unscoped...)

	if p.Distro != nil {
		if name := strings.ToLower(p.Distro.Name()); name != "" {
			dst = append(dst, idx.byDistroName[name]...)
		}
	}

	if p.Type != "" {
		dst = append(dst, idx.byEcosystem[strings.ToLower(string(p.Type))]...)
	}

	slices.SortFunc(dst, func(a, b *compiledSearchRule) int { return a.ord - b.ord })
	return dst
}
