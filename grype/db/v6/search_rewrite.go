package v6

import (
	"slices"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// rewrite returns the searches to run in place of cs, or false when no rule applies and cs is searched
// as is (see SearchRuleProvider.SearchRewrites). A search no rule applies to allocates nothing.
//
// Every matching add or replace rule contributes one search: cs with the rule's OS and/or name (or, for
// a CPE search, CPE vendor and/or product), marked with the rule's priority. cs itself is kept unless a
// matching rule drops it, or a matching rule replaces it and no matching rule adds to it; a drop rule
// contributes no search, so a search every matching rule drops is rewritten to none. Only a drop rule
// or a CPE substitution applies to a CPE search. Each search a rule that applies is logged
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
			log.WithFields("search", own, "rule", &rm.rule.row).Trace("search rule dropped search")
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
		logRuledSearch(own, r, dropsOwnSearch)
		searches = append(searches, r.search.criteria(r.rule.byRule))
	}
	switch {
	case !dropsOwnSearch:
		searches = append(searches, cs)
	case ownRule != nil:
		logRuledSearch(own, ownRule, dropsOwnSearch)
		searches = append(searches, own.criteria(ownRule.rule.byRule))
	}
	return searches, true
}

// logRuledSearch logs the search r's rule runs in place of own, when own is dropped and the rule
// replaces it, else beside it.
func logRuledSearch(own searchParts, r *ruledSearch, ownDropped bool) {
	msg := "search rule added search"
	if ownDropped && r.rule.row.Action == SearchRuleReplace {
		msg = "search rule replaced search"
	}
	log.WithFields("search", own, "new", r.search, "rule", &r.rule.row).Trace(msg)
}

// searchParts is a search split into the criteria rules read or replace, and the rest, which every
// search a rule adds keeps as is.
type searchParts struct {
	name      *search.PackageNameCriteria // nil for none
	ecosystem *search.EcosystemCriteria   // nil for a search by no ecosystem
	distro    *search.DistroCriteria      // nil for the rows of no OS
	cpe       *search.CPECriteria         // nil for a search by no CPE

	// the search as given, of which the criteria at nameAt, ecosystemAt, distroAt and cpeAt (-1 for
	// none) are replaced by name, ecosystem, distro and cpe
	all                                  []vulnerability.Criteria
	nameAt, ecosystemAt, distroAt, cpeAt int

	pkg      *pkg.Package // of the search.WithPackage criteria, which is kept
	upstream bool         // a search.BySourcePackage criteria, which is kept
}

func splitSearch(cs []vulnerability.Criteria) searchParts {
	sp := searchParts{all: cs, nameAt: -1, ecosystemAt: -1, distroAt: -1, cpeAt: -1}
	for i, c := range cs {
		switch c := c.(type) {
		case *search.PackageNameCriteria:
			if sp.name == nil {
				sp.name, sp.nameAt = c, i
			}
		case *search.EcosystemCriteria:
			if sp.ecosystem == nil {
				sp.ecosystem, sp.ecosystemAt = c, i
			}
		case *search.DistroCriteria:
			if sp.distro == nil {
				sp.distro, sp.distroAt = c, i
			}
		case *search.PackageCriteria:
			sp.pkg = &c.Package
		case *search.CPECriteria:
			if sp.cpe == nil {
				sp.cpe, sp.cpeAt = c, i
			}
		case *search.SourcePackageCriteria:
			sp.upstream = true
		}
	}
	return sp
}

// subject returns what the search states about the package it searches for, else p. That is not
// always the cataloged package: matchers search under other names and versions (upstreams, rootio
// names, epoch-patched rpm versions). Only distro and CPE searches have an OS for rules to match; an
// ecosystem search has none. A pattern on something the search does not state does not match. A
// search is of an upstream when it is marked search.BySourcePackage, else of the package itself.
func (sp searchParts) subject(p pkg.Package) searchSubject {
	if sp.pkg != nil {
		p = *sp.pkg
	}
	s := searchSubject{name: p.Name, version: p.Version, upstream: sp.upstream}
	if sp.distro != nil || sp.cpe != nil {
		s.distro = p.Distro
	}
	if sp.cpe != nil {
		s.cpeVendor, s.cpeProduct = sp.cpe.CPE.Attributes.Vendor, sp.cpe.CPE.Attributes.Product
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
// or renames a search that has no name or re-ecosystems one that has no ecosystem: a rule's OS, name
// and ecosystem are one search, so a replacement it cannot apply drops the others too. A CPE search
// reads NVD's rows, which have no OS, name or ecosystem, so a rule can only change its CPE's vendor
// and/or product (or drop it).
func (sp searchParts) ruleSearch(rm matchedRule, s searchSubject) (rs searchParts, ok bool) {
	if sp.cpe != nil {
		return sp.cpeRuleSearch(rm, s)
	}
	d, hasOS, osLess := rm.overlayDistro(s)
	name := rm.expand(rm.rule.packageName, s)
	if name == sp.searchedName() {
		name = ""
	}
	if name != "" && sp.name == nil {
		return rs, false
	}
	eco := rm.expand(rm.rule.ecosystem, s)
	if strings.EqualFold(eco, sp.searchedEcosystem()) {
		eco = ""
	}
	if eco != "" && sp.ecosystem == nil {
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
	case name == "" && eco == "":
		return rs, false
	}
	if name != "" {
		rs.name = &search.PackageNameCriteria{PackageName: name}
	}
	if eco != "" {
		// the store searches the package type when it has one (see searchQueryBuilder.handleEcosystem)
		rs.ecosystem = &search.EcosystemCriteria{Language: sp.ecosystem.Language, PackageType: syftPkg.Type(eco)}
	}
	return rs, true
}

// cpeRuleSearch is ruleSearch for a CPE search: its CPE under the rule's vendor and/or product, where
// an empty expansion keeps the searched one.
func (sp searchParts) cpeRuleSearch(rm matchedRule, s searchSubject) (rs searchParts, ok bool) {
	searched := sp.cpe.CPE
	attrs := searched.Attributes
	if vendor := rm.expand(rm.rule.cpeVendor, s); vendor != "" {
		attrs.Vendor = vendor
	}
	if product := rm.expand(rm.rule.cpeProduct, s); product != "" {
		attrs.Product = product
	}
	if sameCPEProduct(attrs, searched.Attributes) {
		return rs, false
	}
	searched.Attributes = attrs
	rs = sp
	rs.cpe = &search.CPECriteria{CPE: searched}
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

// searchedEcosystem is the ecosystem whose rows the search reads, as searchQueryBuilder.handleEcosystem
// picks it: the package type when it is known, else the language; empty for a search by no ecosystem.
func (sp searchParts) searchedEcosystem() string {
	if sp.ecosystem == nil {
		return ""
	}
	if t := sp.ecosystem.PackageType; t != "" && t != syftPkg.UnknownPkg {
		return string(t)
	}
	if sp.ecosystem.Language != "" {
		return string(sp.ecosystem.Language)
	}
	return string(sp.ecosystem.PackageType)
}

// sameRows is true when both searches read the same rows, by their OS, its aliasing, name, ecosystem
// and CPE vendor and product; the rest is the same across one rewrite.
func (sp searchParts) sameRows(other searchParts) bool {
	return sp.searchedName() == other.searchedName() && strings.EqualFold(sp.searchedEcosystem(), other.searchedEcosystem()) &&
		isExact(sp.distro) == isExact(other.distro) &&
		slices.EqualFunc(distrosOf(sp.distro), distrosOf(other.distro), sameOS) && sameCPE(sp.cpe, other.cpe)
}

func sameCPE(a, b *search.CPECriteria) bool {
	if a == nil || b == nil {
		return a == b
	}
	return sameCPEProduct(a.CPE.Attributes, b.CPE.Attributes)
}

// sameCPEProduct is true for the same CPE vendor and product, which is all a rule changes of a CPE.
func sameCPEProduct(a, b cpe.Attributes) bool {
	return strings.EqualFold(a.Vendor, b.Vendor) && strings.EqualFold(a.Product, b.Product)
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

// String describes the rows the search reads, for logging: its name (at the searched version) or CPE,
// its ecosystem, its OS (name:version(label)+channels), and whether it is for an upstream.
func (sp searchParts) String() string {
	var sb strings.Builder
	switch {
	case sp.cpe != nil:
		sb.WriteString(sp.cpe.CPE.Attributes.BindToFmtString())
	case sp.name != nil:
		sb.WriteString(sp.name.PackageName)
		if sp.pkg != nil && sp.pkg.Version != "" {
			sb.WriteString("@" + sp.pkg.Version)
		}
	}
	if eco := sp.searchedEcosystem(); eco != "" {
		sb.WriteString(" (" + eco + ")")
	}
	sb.WriteString(" in ")
	if sp.distro == nil {
		sb.WriteString("no OS")
	}
	for i, d := range distrosOf(sp.distro) {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(d.Name())
		if d.Version != "" {
			sb.WriteString(":" + d.Version)
		}
		if d.Codename != "" {
			sb.WriteString("(" + d.Codename + ")")
		}
		if len(d.Channels) > 0 {
			sb.WriteString("+" + strings.Join(d.Channels, ","))
		}
	}
	if sp.upstream {
		sb.WriteString(" (upstream)")
	}
	return sb.String()
}

// criteria rebuilds the search, with extra appended.
func (sp searchParts) criteria(extra ...vulnerability.Criteria) []vulnerability.Criteria {
	out := make([]vulnerability.Criteria, 0, len(sp.all)+len(extra)+4)
	if sp.name != nil {
		out = append(out, sp.name)
	}
	if sp.ecosystem != nil {
		out = append(out, sp.ecosystem)
	}
	if sp.distro != nil {
		out = append(out, sp.distro)
	}
	if sp.cpe != nil {
		out = append(out, sp.cpe)
	}
	for i, c := range sp.all {
		if i != sp.nameAt && i != sp.ecosystemAt && i != sp.distroAt && i != sp.cpeAt {
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
