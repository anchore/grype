package v6

import (
	"slices"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// rewrite returns the searches to run in place of cs, or false when no rule applies and cs is searched
// as is (see SearchRuleProvider.SearchRewrites). A search no rule applies to allocates nothing.
//
// Every matching rule adds one search: cs with the rule's OS and/or name, marked with the rule's
// priority. cs itself is kept, except for a CPE search that a rule gives an OS: that search reads the
// OS's CPE rows in place of NVD's.
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
	dropsOwnSearch := false
	for _, rm := range matched {
		rs, givesOS, ok := own.ruleSearch(rm, s)
		if !ok {
			continue
		}
		dropsOwnSearch = dropsOwnSearch || givesOS && own.isCPE
		ruled = addRuledSearch(ruled, ruledSearch{search: rs, rule: rm.rule})
	}
	if len(ruled) == 0 {
		return nil, false
	}

	// a rule can search exactly what cs does (e.g. the rapidfort-alpine rule on a distro search); that
	// only matters when cs is dropped, where cs is then kept at the rule's priority
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

	pkg   *pkg.Package // of the search.WithPackage criteria, which is kept
	isCPE bool
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
			sp.isCPE = true
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
	if sp.distro != nil || sp.isCPE {
		s.distro = p.Distro
	}
	switch {
	case p.Type != "" && p.Type != syftPkg.UnknownPkg:
		s.ecosystem = string(p.Type)
	case p.Language != "":
		s.ecosystem = string(p.Language)
	}
	return s
}

// ruleSearch returns what the rule searches in place of sp, and whether it gives the search an OS. It
// is false when the rule changes nothing, or renames a search that has no name: a rule's OS and name
// are one search, so a rename it cannot apply drops its OS too.
func (sp searchParts) ruleSearch(rm matchedRule, s searchSubject) (rs searchParts, givesOS, ok bool) {
	d, hasOS, osLess := rm.overlayDistro(s)
	name := rm.expand(rm.rule.packageName, s)
	if name == sp.searchedName() {
		name = ""
	}
	if name != "" && sp.name == nil {
		return rs, false, false
	}

	rs = sp
	switch {
	case osLess:
		rs.distro = nil
	case hasOS:
		rs.distro = newDistroCriteria(d, sp.distro != nil && sp.distro.Exact)
		givesOS = true
	case name == "":
		return rs, false, false
	}
	if name != "" {
		rs.name = &search.PackageNameCriteria{PackageName: name}
	}
	return rs, givesOS, true
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

// sameRows is true when both searches read the same rows, by their OS and name; the rest is the same
// across one rewrite.
func (sp searchParts) sameRows(other searchParts) bool {
	return sp.searchedName() == other.searchedName() && slices.EqualFunc(distrosOf(sp.distro), distrosOf(other.distro), sameOS)
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
