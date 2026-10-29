package v6

import (
	"slices"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// rewrite returns the searches to run in place of cs, or false when no rule applies and cs is searched
// as is (see SearchRuleProvider.SearchRewrites). A search no rule applies to allocates nothing.
//
// Every matching add or replace rule contributes one search: cs with the rule's OS and/or name, marked
// with the rule's priority. cs itself is kept unless a matching rule drops it, or a matching rule
// replaces it and no matching rule adds to it; a drop rule contributes no search, so a search every
// matching rule drops is rewritten to none. Only a drop rule applies to a CPE search.
func (idx *searchIndex) rewrite(p pkg.Package, cs []vulnerability.Criteria) ([][]vulnerability.Criteria, bool) {
	own := splitSearch(cs)
	s := own.subject(p)
	var matchedBuf [4]matchedRule
	matched := idx.appendMatchingRules(matchedBuf[:0], s)
	if len(matched) == 0 {
		return nil, false
	}

	var ruledBuf [4]ruledSearch
	ruled := ruledBuf[:0]
	dropped, replaced, added := false, false, false
	for _, rm := range matched {
		switch rm.rule.row.Action {
		case SearchRuleDrop:
			dropped = true
			continue
		case SearchRuleAdd:
			added = true
		}
		rs, ok := own.ruleSearch(rm, s)
		if !ok {
			continue
		}
		replaced = replaced || rm.rule.row.Action == SearchRuleReplace
		ruled = addRuledSearch(ruled, ruledSearch{search: rs, rule: rm.rule})
	}
	dropsOwnSearch := dropped || replaced && !added
	if len(ruled) == 0 && !dropsOwnSearch {
		return nil, false
	}

	// a rule can search exactly what cs does (e.g. a replace rule naming the searched OS); that only
	// matters when cs is dropped, where cs is then kept at the rule's priority
	searches := make([][]vulnerability.Criteria, 0, len(ruled)+1)
	var ownRule *ruledSearch
	for i := range ruled {
		r := &ruled[i]
		if r.search.sameRows(own) {
			ownRule = r
			continue
		}
		searches = append(searches, r.search.criteria(r.rule.byRule))
	}
	switch {
	case !dropsOwnSearch:
		searches = append(searches, cs)
	case ownRule != nil:
		searches = append(searches, own.criteria(ownRule.rule.byRule))
	}
	return searches, true
}

// searchParts is a search split into the criteria rules read or replace, and the rest, which every
// search a rule adds keeps as is.
type searchParts struct {
	name   *search.PackageNameCriteria // nil for none
	distro *search.DistroCriteria      // nil for the rows of no OS

	// the search as given, of which the criteria at nameAt and distroAt (-1 for none) are replaced by
	// name and distro
	all              []vulnerability.Criteria
	nameAt, distroAt int

	pkg *pkg.Package // of the search.WithPackage criteria, which is kept
	cpe *cpe.CPE     // of the search.ByCPE criteria; nil for a search by no CPE
}

func splitSearch(cs []vulnerability.Criteria) searchParts {
	sp := searchParts{all: cs, nameAt: -1, distroAt: -1}
	for i, c := range cs {
		switch c := c.(type) {
		case *search.PackageNameCriteria:
			if sp.name == nil {
				sp.name, sp.nameAt = c, i
			}
		case *search.DistroCriteria:
			if sp.distro == nil {
				sp.distro, sp.distroAt = c, i
			}
		case *search.PackageCriteria:
			sp.pkg = &c.Package
		case *search.CPECriteria:
			if sp.cpe == nil {
				sp.cpe = &c.CPE
			}
		}
	}
	return sp
}

// subject returns what the search states about the package it searches for, else p. That is not
// always the cataloged package: matchers search under other names and versions (upstreams, rootio
// names, epoch-patched rpm versions). Only distro and CPE searches have an OS for rules to match; an
// ecosystem search has none. A pattern on something the search does not state does not match.
func (sp searchParts) subject(p pkg.Package) searchSubject {
	if sp.pkg != nil {
		p = *sp.pkg
	}
	s := searchSubject{name: p.Name, version: p.Version}
	if sp.distro != nil || sp.cpe != nil {
		s.distro = p.Distro
	}
	if sp.cpe != nil {
		s.cpeVendor, s.cpeProduct = sp.cpe.Attributes.Vendor, sp.cpe.Attributes.Product
	}
	switch {
	case p.Type != "" && p.Type != syftPkg.UnknownPkg:
		s.ecosystem = string(p.Type)
	case p.Language != "":
		s.ecosystem = string(p.Language)
	}
	return s
}

// ruleSearch returns what the rule searches in place of sp. It is false when the rule changes nothing,
// or renames a search that has no name: a rule's OS and name are one search, so a rename it cannot
// apply drops its OS too. A CPE search reads NVD's rows, which have no OS, so a rule can only drop it.
func (sp searchParts) ruleSearch(rm matchedRule, s searchSubject) (rs searchParts, ok bool) {
	if sp.cpe != nil {
		return rs, false
	}
	d, hasOS, osLess := rm.overlayDistro(s)
	name := rm.expand(rm.rule.packageName, s)
	if name == sp.searchedName() {
		name = ""
	}
	if name != "" && sp.name == nil {
		return rs, false
	}

	rs = sp
	switch {
	case osLess:
		rs.distro = nil
	case hasOS:
		// an OS the rule names is searched as named, not under its alias (e.g. almalinux's own rows
		// rather than rhel's); a channel of the searched OS keeps the search's aliasing
		exact := rm.rule.row.ReplacementDistroName != nil || sp.distro != nil && sp.distro.Exact
		rs.distro = newDistroCriteria(d, exact)
	case name == "":
		return rs, false
	}
	if name != "" {
		rs.name = &search.PackageNameCriteria{PackageName: name}
	}
	return rs, true
}

// distroSearch is a DistroCriteria with its one distro, in one allocation.
type distroSearch struct {
	criteria search.DistroCriteria
	distros  [1]distro.Distro
}

func newDistroCriteria(d distro.Distro, exact bool) *search.DistroCriteria {
	ds := &distroSearch{distros: [1]distro.Distro{d}}
	ds.criteria = search.DistroCriteria{Distros: ds.distros[:], Exact: exact}
	return &ds.criteria
}

func (sp searchParts) searchedName() string {
	if sp.name == nil {
		return ""
	}
	return sp.name.PackageName
}

// sameRows is true when both searches read the same rows, by their OS, its aliasing and name; the rest
// is the same across one rewrite.
func (sp searchParts) sameRows(other searchParts) bool {
	return sp.searchedName() == other.searchedName() && isExact(sp.distro) == isExact(other.distro) &&
		slices.EqualFunc(distrosOf(sp.distro), distrosOf(other.distro), sameOS)
}

func isExact(c *search.DistroCriteria) bool {
	return c != nil && c.Exact
}

func distrosOf(c *search.DistroCriteria) []distro.Distro {
	if c == nil {
		return nil
	}
	return c.Distros
}

func sameOS(a, b distro.Distro) bool {
	return strings.EqualFold(a.Name(), b.Name()) && a.Version == b.Version && strings.EqualFold(a.Codename, b.Codename) &&
		slices.EqualFunc(a.Channels, b.Channels, strings.EqualFold)
}

// criteria rebuilds the search, with extra appended.
func (sp searchParts) criteria(extra ...vulnerability.Criteria) []vulnerability.Criteria {
	out := make([]vulnerability.Criteria, 0, len(sp.all)+len(extra)+2)
	if sp.name != nil {
		out = append(out, sp.name)
	}
	if sp.distro != nil {
		out = append(out, sp.distro)
	}
	for i, c := range sp.all {
		if i != sp.nameAt && i != sp.distroAt {
			out = append(out, c)
		}
	}
	return append(out, extra...)
}

type ruledSearch struct {
	search searchParts
	rule   *searchMatch
}

// addRuledSearch keeps the highest priority of the rules that read the same rows.
func addRuledSearch(searches []ruledSearch, r ruledSearch) []ruledSearch {
	i := slices.IndexFunc(searches, func(existing ruledSearch) bool { return existing.search.sameRows(r.search) })
	switch {
	case i < 0:
		return append(searches, r)
	case r.rule.row.Priority > searches[i].rule.row.Priority:
		searches[i] = r
	}
	return searches
}
