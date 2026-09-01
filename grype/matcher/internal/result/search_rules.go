package result

import (
	"slices"
	"strings"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

// A provider's search rules are data-defined statements about how one package's lookup should be
// performed: which OperatingSystem rows are read (a release channel a rebuild publishes under,
// another vendor's OS name) and which additional names are searched. This file turns the rules that
// apply to a package into the searches to run in its place, so a matcher asks for the package it
// cataloged and the rules decide what that means.
//
// The package's own search always stands; a rule adds to what is searched for it. Each search
// carries how confidently the data it reads speaks for the package, recorded on the match details it
// produces (see match.ConfidenceDetail) so nothing downstream has to re-derive it from what a record
// looks like: a stream ranks above the package's own data, having been selected for this package in
// particular -- a release channel, or another vendor's OS identity a rule routed it to -- so it
// describes this build where the package's own data describes the release the build sits in.
const (
	confidenceStream = 1.0
	confidenceOwn    = 0.75
)

// searchRuleProvider is the optional interface a vulnerability provider implements to expose the
// rules that apply to a package. A provider that does not leaves every search as the matcher made it.
type searchRuleProvider interface {
	SearchRules(p pkg.Package) []v6.SearchRule
}

// ruledSearch is one store search to run for a criteria set, and what its rows are to the package.
type ruledSearch struct {
	criteria []vulnerability.Criteria

	// stream names the OS identity this search reads, for the audit trail on the match details;
	// empty for the package's own data
	stream string

	// confidence is how confidently that data speaks for the package; 0 for a search no rule
	// spoke about, which leaves it unranked against the others
	confidence float64
}

// applySearchRules passes one criteria set through the rules that apply to the package, returning the
// searches to run in its place. A package no rule speaks for -- or a provider with no rules --
// yields the search exactly as the matcher made it, unranked.
func applySearchRules(vp vulnerability.Provider, catalogedPkg pkg.Package, cs []vulnerability.Criteria) []ruledSearch {
	unruled := []ruledSearch{{criteria: cs}}

	rp, ok := vp.(searchRuleProvider)
	if !ok {
		return unruled
	}
	rules := rp.SearchRules(catalogedPkg)
	if len(rules) == 0 {
		return unruled
	}

	distroIdx, nameIdx, version := searchDimensions(cs)

	out := ruledSearchSet{}
	// the package's own search, unchanged
	out.add(cs, distroIdx, "", confidenceOwn)

	for _, r := range rules {
		for _, d := range overlayDistros(r, cs, distroIdx, version) {
			out.add(withDistro(cs, distroIdx, d), distroIdx, streamName(d), confidenceStream)
		}
	}

	return fanOutNames(out.searches, rules, cs, nameIdx)
}

// ruledSearchSet accumulates the searches to run, dropping the ones that would read rows another
// already reads: an overlay whose channel expanded empty selects the very same rows as the package's
// own search, and the first search to claim them keeps its confidence.
type ruledSearchSet struct {
	searches []ruledSearch
	seen     map[string]struct{}
}

func (s *ruledSearchSet) add(cs []vulnerability.Criteria, distroIdx int, stream string, confidence float64) {
	key := searchKey(cs, distroIdx)
	if s.seen == nil {
		s.seen = map[string]struct{}{}
	}
	if _, ok := s.seen[key]; ok {
		return
	}
	s.seen[key] = struct{}{}
	s.searches = append(s.searches, ruledSearch{criteria: cs, stream: stream, confidence: confidence})
}

// searchKey identifies the OS rows a search reads. Two searches with the same key read the same rows,
// whichever rule named them.
func searchKey(cs []vulnerability.Criteria, distroIdx int) string {
	if distroIdx < 0 {
		return ""
	}
	dc, ok := cs[distroIdx].(*search.DistroCriteria)
	if !ok {
		return ""
	}
	var out []string
	for _, d := range dc.Distros {
		out = append(out, strings.ToLower(d.Name())+"@"+d.Version+"@"+strings.ToLower(d.Codename)+"+"+strings.ToLower(strings.Join(d.Channels, ",")))
	}
	return strings.Join(out, "|")
}

// searchDimensions locates the criteria a rule can rewrite -- the distro rows read and the name
// searched -- along with the version the search was made at, which is what a channel template
// resolves its capture groups from.
func searchDimensions(cs []vulnerability.Criteria) (distroIdx, nameIdx int, version string) {
	distroIdx, nameIdx = -1, -1
	for i, c := range cs {
		switch c := c.(type) {
		case *search.DistroCriteria:
			if distroIdx < 0 {
				distroIdx = i
			}
		case *search.PackageNameCriteria:
			nameIdx = i
		case *search.VersionCriteria:
			version = c.Version.Raw
		case *search.PackageVersionCriteria:
			version = c.Version.Raw
		}
	}
	return distroIdx, nameIdx, version
}

// overlayDistros is the OS identity a rule selects in addition to each of the searched ones: a
// channel selected from the package's version markers, and/or another vendor's OS name.
//
// A rule with distro predicates only speaks for the distros it named, which is what lets one rule set
// serve a search that carries several OS specifiers. For an OS-less search there is no release to
// carry, so only an OS-name substitution applies and it resolves version-free -- which fits vendors
// whose OS identity is rolling (e.g. echo alongside debian's OS-less ecosystem rows).
func overlayDistros(r v6.SearchRule, cs []vulnerability.Criteria, distroIdx int, version string) []distro.Distro {
	if r.ReplacementChannel == nil && r.ReplacementDistroName == nil {
		return nil
	}
	if r.IsDistrolessSearch() {
		// an empty OS name means search the default non-distro records, e.g. CPE-indexed (NVD), for which are no operating system associated
		return nil
	}
	channel := r.ExpandChannel(version)

	if distroIdx < 0 {
		if r.ReplacementDistroName == nil {
			return nil // a channel needs a searched OS to apply to
		}
		return []distro.Distro{*distro.New(distro.TypeFromID(*r.ReplacementDistroName), "", "")}
	}

	dc, ok := cs[distroIdx].(*search.DistroCriteria)
	if !ok {
		return nil
	}

	var out []distro.Distro
	for _, d := range dc.Distros {
		if r.MatchDistroName != "" && !strings.EqualFold(r.MatchDistroName, d.Name()) {
			continue
		}

		overlay := d
		overlay.Channels = nil
		if r.ReplacementDistroName != nil {
			// the replacement is an OS id, which is not always the distro name it resolves to ("ol"
			// names oraclelinux), so it is normalized the way a detected distro would be. The
			// codename is dropped: it is the base vendor's release label, and another vendor's OS
			// records are version-keyed with no codename of their own.
			overlay = *distro.New(distro.TypeFromID(*r.ReplacementDistroName), d.Version, "")
		}
		if channel != "" {
			overlay.Channels = []string{channel}
		}
		out = append(out, overlay)
	}
	return out
}

// withDistro is the criteria set with its distro dimension replaced by d. An OS-less search gains
// one it never had, which is how a vendor's OS rows are reached from an ecosystem search.
func withDistro(cs []vulnerability.Criteria, distroIdx int, d distro.Distro) []vulnerability.Criteria {
	out := slices.Clone(cs)
	dc := &search.DistroCriteria{Distros: []distro.Distro{d}}
	if distroIdx < 0 {
		return append(out, dc)
	}
	// the rule replaces which OS rows are read, nothing else about how they are read, so the
	// original search's aliasing choice carries over
	if original, ok := cs[distroIdx].(*search.DistroCriteria); ok {
		dc.Exact = original.Exact
	}
	out[distroIdx] = dc
	return out
}

// fanOutNames adds, for every search and every additional name the rules contribute, the same search
// under that name. Derived names are not themselves re-expanded.
//
// Only the first search keeps the CPE dimension: rules never rewrite it, so every additional search
// would otherwise read exactly the same CPE rows again.
func fanOutNames(searches []ruledSearch, rules []v6.SearchRule, cs []vulnerability.Criteria, nameIdx int) []ruledSearch {
	names := additionalNames(rules, cs, nameIdx)

	out := make([]ruledSearch, 0, len(searches)*(1+len(names)))
	for _, s := range searches {
		out = append(out, s)
		for _, n := range names {
			withName := s
			withName.criteria = slices.Clone(s.criteria)
			withName.criteria[nameIdx] = search.ByPackageName(n)
			out = append(out, withName)
		}
	}

	for i := range out {
		if i == 0 {
			continue
		}
		out[i].criteria = withoutCPECriteria(out[i].criteria)
	}
	return out
}

// additionalNames is the extra names the rules contribute for the searched name, in first-seen order
// and excluding the searched name itself.
func additionalNames(rules []v6.SearchRule, cs []vulnerability.Criteria, nameIdx int) []string {
	if nameIdx < 0 {
		return nil
	}
	nc, ok := cs[nameIdx].(*search.PackageNameCriteria)
	if !ok || nc.PackageName == "" {
		return nil
	}

	var out []string
	seen := map[string]struct{}{nc.PackageName: {}}
	for _, r := range rules {
		variant := r.ExpandPackageName(nc.PackageName)
		if variant == "" {
			continue
		}
		if _, ok := seen[variant]; ok {
			continue
		}
		seen[variant] = struct{}{}
		out = append(out, variant)
	}
	return out
}

func withoutCPECriteria(cs []vulnerability.Criteria) []vulnerability.Criteria {
	out := make([]vulnerability.Criteria, 0, len(cs))
	for _, c := range cs {
		if _, ok := c.(*search.CPECriteria); ok {
			continue
		}
		out = append(out, c)
	}
	return out
}

// streamName names the OS identity a resolved search reads, for the audit trail on its match details.
func streamName(d distro.Distro) string {
	out := d.Name()
	if len(d.Channels) > 0 {
		out += "+" + strings.Join(d.Channels, ",")
	}
	return out
}
