package v6

import (
	"slices"
	"strings"
)

// searchRuleIndex is the compiled, queryable form of the search rule set. Rule selection is dominated
// by the two predicates that are exact case-insensitive compares rather than patterns —
// MatchDistroName and MatchEcosystem — so rules are filed by those and a query only ever evaluates the
// rules that could possibly match it. The regex predicates then decide, exactly as they did when every
// rule was scanned linearly: the index only narrows the candidate set, so it cannot change which rules
// apply.
//
// The point is that cost stops tracking how many rules exist and starts tracking how many share a
// query's distro and ecosystem. That matters because the rule set is data (see KnownSearchRules, whose
// TODO anticipates vunnel providers contributing rules directly) rather than a fixed list.
type searchRuleIndex struct {
	// rules is the compiled set in the order it was read; the buckets below hold the same pointers,
	// so a rule is stored once however many ways it can be reached
	rules []*compiledSearchRule

	// byDistroName files rules with a MatchDistroName, keyed by its lowercased value. Such a rule can
	// only match a query carrying that distro, so a query's OS specifiers select its buckets directly.
	byDistroName map[string]*ruleBucket

	// byEcosystem files rules with no distro name but a MatchEcosystem, which requires the query to
	// carry an ecosystem and is therefore unreachable from distro queries.
	byEcosystem map[string]*ruleBucket

	// unscoped holds rules with neither exact predicate — candidates for every query, and the one
	// shape the index cannot narrow. KnownSearchRules has none.
	unscoped ruleBucket
}

// ruleBucket holds the rules filed under one distro name or ecosystem, sub-filed by exact package name
// where the rule's name pattern decomposed to one (see patternShape). That sub-index is what keeps a
// bucket from becoming its own linear scan: a provider emitting one rule per package puts thousands of
// rules under a single distro, every one of them naming an exact package.
type ruleBucket struct {
	byExactName map[string][]*compiledSearchRule
	rest        []*compiledSearchRule
}

func (b *ruleBucket) add(r *compiledSearchRule) {
	if r.pkgNameShape.isExact() {
		if b.byExactName == nil {
			b.byExactName = make(map[string][]*compiledSearchRule)
		}
		name := r.pkgNameShape.exact
		b.byExactName[name] = append(b.byExactName[name], r)
		return
	}
	b.rest = append(b.rest, r)
}

// appendCandidates adds the bucket's rules that could match a query for the given package name. A nil
// bucket is the common case — a query whose distro no rule speaks for — and contributes nothing.
func (b *ruleBucket) appendCandidates(dst []*compiledSearchRule, pkgName string) []*compiledSearchRule {
	if b == nil {
		return dst
	}
	if pkgName != "" && len(b.byExactName) > 0 {
		// a rule naming an exact package cannot match a query that constrains no name, so the
		// sub-index is only consulted when there is a name to look up
		dst = append(dst, b.byExactName[pkgName]...)
	}
	return append(dst, b.rest...)
}

func newSearchRuleIndex(rows []SearchRule) *searchRuleIndex {
	idx := &searchRuleIndex{rules: compileSearchRules(rows)}

	for i, r := range idx.rules {
		r.ord = i

		// a rule is filed under exactly one key, so buckets are disjoint and gathering candidates from
		// several of them needs no deduplication. Distro name wins over ecosystem: a rule naming a
		// distro requires that distro whatever its ecosystem predicate says.
		switch {
		case r.row.MatchDistroName != "":
			bucketFor(&idx.byDistroName, strings.ToLower(r.row.MatchDistroName)).add(r)
		case r.row.MatchEcosystem != "":
			bucketFor(&idx.byEcosystem, strings.ToLower(r.row.MatchEcosystem)).add(r)
		default:
			idx.unscoped.add(r)
		}
	}

	return idx
}

func bucketFor(m *map[string]*ruleBucket, key string) *ruleBucket {
	if *m == nil {
		*m = make(map[string]*ruleBucket)
	}
	b, ok := (*m)[key]
	if !ok {
		b = &ruleBucket{}
		(*m)[key] = b
	}
	return b
}

// candidates appends the rules that could match the query to dst, in the order the rules were read.
// Restoring that order is what makes resolution byte-identical to a linear scan over the whole set,
// which is the entire safety argument for indexing: rule order decides the order of the resolved OS
// specifiers and of the fanned-out queries, and so reaches the match details in grype's output.
func (idx *searchRuleIndex) candidates(q *searchQuery, dst []*compiledSearchRule) []*compiledSearchRule {
	if idx == nil || len(idx.rules) == 0 {
		return dst
	}

	pkgName := q.packageName()
	dst = idx.unscoped.appendCandidates(dst, pkgName)

	for i, spec := range q.osSpecs {
		if spec == nil {
			continue // the "any OS" specifier names no distro
		}
		name := strings.ToLower(spec.Name)
		if name == "" || osNameSeenBefore(q.osSpecs, i, name) {
			continue
		}
		dst = idx.byDistroName[name].appendCandidates(dst, pkgName)
	}

	if q.pkgType != "" {
		dst = idx.byEcosystem[strings.ToLower(string(q.pkgType))].appendCandidates(dst, pkgName)
	}

	slices.SortFunc(dst, func(a, b *compiledSearchRule) int { return a.ord - b.ord })
	return dst
}

// osNameSeenBefore reports whether an earlier specifier already contributed this distro name's bucket.
// A query legitimately carries the same OS more than once — handleDistro emits one specifier per
// channel, and the eus/esm matchers search a distro alongside its channel-less form — and visiting a
// bucket twice would return its rules twice.
func osNameSeenBefore(specs OSSpecifiers, upto int, name string) bool {
	for _, prev := range specs[:upto] {
		if prev != nil && strings.EqualFold(prev.Name, name) {
			return true
		}
	}
	return false
}
