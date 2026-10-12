package v6

import (
	"slices"
	"strings"

	"github.com/anchore/grype/internal/log"
)

// searchIndex is a node of the rule index over exact values. A rule is filed under its exact package
// name, then distro name, then ecosystem (skipping those it has no exact value for), then down a chain
// of regexMatch nodes, one per remaining pattern, ending at its match. Rules with the same pattern at
// the same place share its regexMatch, so it runs once for all of them.
//
// A search walks, at every node it reaches, the maps for its own values and every regexMatch that
// matches; each rule has one path, so a search reaches it at most once.
type searchIndex struct {
	byPackageName map[string]*searchIndex
	byDistroName  map[string]*searchIndex
	byEcosystem   map[string]*searchIndex
	remaining     []*regexMatch
	matches       []*searchMatch // rules with no pattern beyond their exact values
}

// newSearchIndex skips invalid rows with a warning.
func newSearchIndex(rows []SearchRule) *searchIndex {
	root := &searchIndex{}
	for i, row := range rows {
		r, err := compileSearchRule(row)
		if err != nil {
			log.WithFields("error", err, "distro", row.MatchDistroName, "ecosystem", row.MatchEcosystem).Warn("skipping invalid search rule")
			continue
		}

		n := root
		n = n.child(&n.byPackageName, r.keys.packageName)
		n = n.child(&n.byDistroName, r.keys.distroName)
		n = n.child(&n.byEcosystem, r.keys.ecosystem)
		r.match.order = i // relative only, so a skipped row's gap is harmless

		// descend the chain of the rule's patterns, reusing a node with the same pattern
		matches, siblings := &n.matches, &n.remaining
		for _, rm := range r.patterns {
			i := slices.IndexFunc(*siblings, rm.sameAs)
			if i < 0 {
				*siblings = append(*siblings, rm)
				i = len(*siblings) - 1
			}
			matches, siblings = &(*siblings)[i].matches, &(*siblings)[i].next
		}
		*matches = append(*matches, r.match)
	}
	return root
}

// child returns the node under key in m, or n itself for an empty key.
func (n *searchIndex) child(m *map[string]*searchIndex, key string) *searchIndex {
	if key == "" {
		return n
	}
	c := (*m)[key]
	if c == nil {
		if *m == nil {
			*m = map[string]*searchIndex{}
		}
		c = &searchIndex{}
		(*m)[key] = c
	}
	return c
}

// appendMatchingRules appends the rules s matches to dst, in read order.
func (n *searchIndex) appendMatchingRules(dst []matchedRule, s searchSubject) []matchedRule {
	if n == nil {
		return dst
	}
	out := n.walk(s, dst)
	slices.SortFunc(out[len(dst):], func(a, b matchedRule) int { return a.rule.order - b.rule.order })
	return out
}

// walk skips the maps no rule was filed in, so a search lowercases a value only to look it up; a value
// the search does not state misses, as no rule is filed under an empty key. Nothing is captured above
// the regexMatch nodes.
func (n *searchIndex) walk(s searchSubject, out []matchedRule) []matchedRule {
	if n == nil {
		return out
	}
	for _, m := range n.matches {
		out = append(out, matchedRule{rule: m})
	}
	if len(n.byPackageName) > 0 {
		out = n.byPackageName[strings.ToLower(s.name)].walk(s, out)
	}
	if len(n.byDistroName) > 0 {
		out = n.byDistroName[strings.ToLower(distroNameOf(s.distro))].walk(s, out)
	}
	if len(n.byEcosystem) > 0 {
		out = n.byEcosystem[strings.ToLower(s.ecosystem)].walk(s, out)
	}
	for _, rm := range n.remaining {
		out = rm.walk(s, nil, out)
	}
	return out
}
