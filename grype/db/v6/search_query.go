package v6

import (
	"fmt"

	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// searchQuery is the complete description of one search: the specifiers to query the store with, and
// the criteria that could not be expressed as a query and must be applied to its results.
type searchQuery struct {
	pkgSpec        *PackageSpecifier
	cpeSpec        *cpe.Attributes
	osSpecs        OSSpecifiers
	vulnSpecs      VulnerabilitySpecifiers
	pkgType        syftPkg.Type
	versionMatcher search.VersionConstraintMatcher
	unaffectedOnly bool

	// version is the raw version of the package being searched for, recorded so search rules can
	// route by version markers (see applySearchRules). Results are constrained by versionMatcher;
	// this field never filters anything.
	version string

	// filters are the criteria that could not be expressed as a query and must be applied to this
	// search's results. Carrying them on the query rather than returning them alongside is what lets
	// the queries a criteria set fans out into be run as one flat list (see newSearchQueries).
	filters []vulnerability.Criteria
}

// newSearchQueries resolves criteria into the flat list of searches to run. There are two independent
// expansions: CriteriaIterator turns or-groups into individual criteria sets, and each set may be
// fanned out further by the search rules (see applySearchRules). Both are unioned by the caller, so
// they are flattened into one list here rather than nested at the call site.
func newSearchQueries(criteria []vulnerability.Criteria, rules *searchRuleIndex) ([]*searchQuery, error) {
	var out []*searchQuery
	for _, criteriaSet := range search.CriteriaIterator(criteria) {
		queries, err := newSearchQuery(criteriaSet, rules)
		if err != nil {
			return nil, err
		}
		if out == nil {
			// a single criteria set is the common case by far, and its queries are the whole answer
			out = queries
			continue
		}
		out = append(out, queries...)
	}
	return out, nil
}

// newSearchQuery parses one criteria set into the queries to run for it: the parsed query, passed
// through the search rules, which may rewrite which OS rows are queried (e.g. a release-stream
// channel selected from a version marker) and fan the search out (e.g. a vendor's own OS identity or
// naming scheme searched alongside the requested data).
func newSearchQuery(criteriaSet []vulnerability.Criteria, rules *searchRuleIndex) ([]*searchQuery, error) {
	builder := newSearchQueryBuilder()

	if err := builder.ApplyCriteria(criteriaSet); err != nil {
		return nil, err
	}

	return builder.Build(rules)
}

// newPackageSearchQuery is the query view of a package considered on its own, rather than of one of
// the criteria sets a search for it produces. Unlike a criteria set — which carries only what its
// query shape provides — a package carries every subject at once, so both OS-scoped and
// ecosystem-scoped rules can be evaluated against it. Only the fields rules read are populated: this
// is never used to query the store.
func newPackageSearchQuery(p pkg.Package) *searchQuery {
	q := &searchQuery{
		pkgSpec: &PackageSpecifier{Name: p.Name},
		pkgType: p.Type,
		version: p.Version,
	}
	if p.Distro != nil {
		q.osSpecs = appendOSSpecifiersForDistro(nil, *p.Distro, false)
	}
	if len(q.osSpecs) == 0 {
		q.osSpecs = append(q.osSpecs, NoOSSpecified)
	}
	return q
}

// packageName is the name being searched for, or "" when the query does not constrain by name.
func (q *searchQuery) packageName() string {
	if q.pkgSpec == nil {
		return ""
	}
	return q.pkgSpec.Name
}

// isOSLess reports whether the query searches data stored without an OS, which is the specifier
// setDefaultOS installs when a criteria set names no distro at all.
func (q *searchQuery) isOSLess() bool {
	return len(q.osSpecs) == 1 && q.osSpecs[0] != nil && *q.osSpecs[0] == *NoOSSpecified
}

// clone returns a shallow copy to rewrite. The specifiers it points at are shared with the original,
// so a caller changing one must replace it rather than edit it in place.
func (q *searchQuery) clone() *searchQuery {
	out := *q
	return &out
}

func (q *searchQuery) withOSSpecs(specs OSSpecifiers) *searchQuery {
	out := q.clone()
	out.osSpecs = specs
	return out
}

func (q *searchQuery) withPackageName(name string) *searchQuery {
	out := q.clone()
	spec := *q.pkgSpec
	spec.Name = name
	out.pkgSpec = &spec
	return out
}

// searchQueryBuilder provides a structured way to build searchQuery objects
// from vulnerability criteria, replacing the large switch statement with focused handler methods.
type searchQueryBuilder struct {
	query             *searchQuery
	remainingCriteria []vulnerability.Criteria
}

// newSearchQueryBuilder creates a new searchQueryBuilder with an empty query
func newSearchQueryBuilder() *searchQueryBuilder {
	return &searchQueryBuilder{
		query:             &searchQuery{},
		remainingCriteria: make([]vulnerability.Criteria, 0),
	}
}

// ApplyCriteria processes all criteria using type-switch dispatch to individual handlers
func (b *searchQueryBuilder) ApplyCriteria(criteriaSet []vulnerability.Criteria) error {
	for _, c := range criteriaSet {
		applied := false

		switch c := c.(type) {
		case *search.PackageNameCriteria:
			b.handlePackageName(c)
			applied = true
		case *search.UnaffectedCriteria:
			b.handleUnaffected(c)
			applied = true
		case *search.EcosystemCriteria:
			b.handleEcosystem(c)
			applied = true
		case *search.IDCriteria:
			b.handleID(c)
			applied = true
		case *search.CPECriteria:
			if err := b.handleCPE(c); err != nil {
				return err
			}
			applied = true
		case *search.DistroCriteria:
			b.handleDistro(c)
			applied = true
		case *search.VersionCriteria:
			// the version constrains results and is applied as a filter (see extractVersionMatcher);
			// the raw value is recorded here as well so search rules can route by version markers.
			// Deliberately not marked applied — the criteria must still reach the version matcher.
			b.query.version = c.Version.Raw
		case *search.PackageVersionCriteria:
			// carries the searched package's version for search resolution (see searchQuery.version)
			// without constraining results; nothing to query or filter by
			b.query.version = c.Version.Raw
			applied = true
		}

		if !applied {
			b.remainingCriteria = append(b.remainingCriteria, c)
		}
	}
	return nil
}

func (b *searchQueryBuilder) handlePackageName(c *search.PackageNameCriteria) {
	if b.query.pkgSpec == nil {
		b.query.pkgSpec = &PackageSpecifier{}
	}
	b.query.pkgSpec.Name = c.PackageName
}

func (b *searchQueryBuilder) handleUnaffected(_ *search.UnaffectedCriteria) {
	b.query.unaffectedOnly = true
}

func (b *searchQueryBuilder) handleEcosystem(c *search.EcosystemCriteria) {
	if b.query.pkgSpec == nil {
		b.query.pkgSpec = &PackageSpecifier{}
	}

	// the v6 store normalizes ecosystems around the syft package type, so that field is preferred
	switch {
	case c.PackageType != "" && c.PackageType != syftPkg.UnknownPkg:
		// prefer to match by a non-blank, known package type
		b.query.pkgType = c.PackageType
		b.query.pkgSpec.Ecosystem = string(c.PackageType)
	case c.Language != "":
		// if there's no known package type, but there is a non-blank language try that
		b.query.pkgSpec.Ecosystem = string(c.Language)
	case c.PackageType == syftPkg.UnknownPkg:
		// if language is blank, and package type is explicitly "UnknownPkg" and not just blank, use that
		b.query.pkgType = c.PackageType
		b.query.pkgSpec.Ecosystem = string(c.PackageType)
	}
}

func (b *searchQueryBuilder) handleID(c *search.IDCriteria) {
	b.query.vulnSpecs = append(b.query.vulnSpecs, VulnerabilitySpecifier{
		Name: c.ID,
	})
}

func (b *searchQueryBuilder) handleCPE(c *search.CPECriteria) error {
	if b.query.cpeSpec == nil {
		b.query.cpeSpec = &cpe.Attributes{}
	}
	*b.query.cpeSpec = c.CPE.Attributes

	if b.query.cpeSpec.Product == cpe.Any {
		return fmt.Errorf("must specify product to search by CPE; got: %s", c.CPE.Attributes.BindToFmtString())
	}

	if b.query.pkgSpec == nil {
		b.query.pkgSpec = &PackageSpecifier{}
	}
	b.query.pkgSpec.CPE = &c.CPE.Attributes

	return nil
}

func (b *searchQueryBuilder) handleDistro(c *search.DistroCriteria) {
	for _, d := range c.Distros {
		b.query.osSpecs = appendOSSpecifiersForDistro(b.query.osSpecs, d, c.Exact)
	}
}

// appendOSSpecifiersForDistro flattens a distro into one OS specifier per channel — or a single
// channel-less specifier when it has none — which is the form the package store queries by. It appends
// rather than returning its own slice because it is called once per queried distro on every search.
func appendOSSpecifiersForDistro(dst OSSpecifiers, d distro.Distro, disableAliasing bool) OSSpecifiers {
	spec := OSSpecifier{
		Name:             d.Name(),
		MajorVersion:     d.MajorVersion(),
		MinorVersion:     d.MinorVersion(),
		RemainingVersion: d.RemainingVersion(),
		LabelVersion:     d.LabelVersion(),
		DisableAliasing:  disableAliasing,
	}

	var found int
	for _, channel := range d.Channels {
		if channel == "" {
			// an empty channel is not a channel, and must not become a channel filter
			continue
		}
		found++
		withChannel := spec
		withChannel.Channel = channel
		dst = append(dst, &withChannel)
	}
	if found == 0 {
		dst = append(dst, &spec)
	}
	return dst
}

// setDefaultOS sets default OS if none specified
func (b *searchQueryBuilder) setDefaultOS() {
	if len(b.query.osSpecs) == 0 {
		// we don't want to search across all distros, instead if the user did not specify a distro we should assume that
		// they want to search across affected packages not associated with any distro.
		b.query.osSpecs = append(b.query.osSpecs, NoOSSpecified)
	}
}

// normalizePackageName normalizes package name if needed
func (b *searchQueryBuilder) normalizePackageName() {
	if b.query.pkgType != "" && b.query.pkgSpec != nil && b.query.pkgSpec.Name != "" {
		b.query.pkgSpec.Name = name.Normalize(b.query.pkgSpec.Name, b.query.pkgType)
	}
}

// extractVersionMatcher extracts version constraints from remaining criteria
func (b *searchQueryBuilder) extractVersionMatcher() {
	var remaining []vulnerability.Criteria
	var matcher search.VersionConstraintMatcher

	for _, c := range b.remainingCriteria {
		if nextMatcher, ok := c.(search.VersionConstraintMatcher); ok {
			if matcher == nil {
				matcher = nextMatcher
			} else {
				matcher = search.MultiConstraintMatcher(matcher, nextMatcher)
			}
		} else {
			remaining = append(remaining, c)
		}
	}

	b.query.versionMatcher = matcher
	b.remainingCriteria = remaining
}

// Build finishes the query and passes it through the search rules, returning the queries to run.
func (b *searchQueryBuilder) Build(rules *searchRuleIndex) ([]*searchQuery, error) {
	b.setDefaultOS()
	b.normalizePackageName()
	b.extractVersionMatcher()
	b.query.filters = b.remainingCriteria

	// rules run last, on the finished query: they select by the normalized package name and the
	// resolved OS specifiers, and every query they produce shares this one's filters
	return applySearchRules(rules, b.query), nil
}
