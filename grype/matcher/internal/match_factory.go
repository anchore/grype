package internal

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

const (
	// confidence levels for different match types
	exactMatchConfidence = 1.0
	cpeMatchConfidence   = 0.9
	defaultConfidence    = 0.0
)

// advisory represents a claim of something being vulnerable and has optional fix information available.
type advisory struct {
	Config               *DisclosureConfig
	Vulnerability        vulnerability.Vulnerability
	ExistingMatchDetails []match.Detail
}

// resolution represents the conclusion of a vulnerability being fixed, wont-fixed, or not-fixed, and the specifics thereof.
type resolution struct {
	vulnerability.Reference
	Fix        vulnerability.Fix
	Constraint version.Constraint
}

type MatchFactory struct {
	ids             *strset.Set
	pkg             pkg.Package // the package that is being matched against
	disclosuresByID map[string][]advisory
	resolutionsByID map[string][]resolution
}

type MatchDetailPrototype struct {
	// Type is the type of match that was made, e.g. ExactDirectMatch, CPEMatch, etc.
	RefPackage *pkg.Package

	// Matcher is the matcher that was used to make the match e.g. RPMMatcher, DebMatcher, etc.
	Matcher match.MatcherType

	SearchedBy any // the parameters that were used to search for the match, e.g. DistroParameters, CPEParameters, EcosystemParameters
}

type DisclosureConfig struct {
	// KeepFixVersions is a flag that indicates whether to keep the fix versions that are embedded within the vulnerability objects.
	KeepFixVersions bool

	// FoundGenerator is a function that returns the "found" information for the disclosure when creating a match.
	FoundGenerator func(vulnerability.Vulnerability) any

	// MatchDetailPrototype is information that will be used to create the match details.
	MatchDetailPrototype MatchDetailPrototype

	// pkgVersion is the version object of the package used when matching against the vulnerability constraint.
	pkgVersion *version.Version
}

func NewMatchFactory(p pkg.Package) *MatchFactory {
	return &MatchFactory{
		pkg:             p,
		ids:             strset.New(),
		disclosuresByID: make(map[string][]advisory),
		resolutionsByID: make(map[string][]resolution),
	}
}

func (c *MatchFactory) AddMatchesAsDisclosures(cfg DisclosureConfig, ms ...match.Match) {
	for _, d := range matchesToDisclosure(&cfg, ms...) {
		c.addDisclosure(&cfg, d)
	}
}

func (c *MatchFactory) AddVulnsAsDisclosures(cfg DisclosureConfig, vs ...vulnerability.Vulnerability) {
	for _, d := range vulnsToDisclosure(vs...) {
		c.addDisclosure(&cfg, d)
	}
}

func (c *MatchFactory) addDisclosure(cfg *DisclosureConfig, d advisory) {
	cfg.pkgVersion = version.NewVersionFromPkg(c.pkg)
	d.Config = cfg

	if d.Vulnerability.ID == "" {
		return // we cannot add a disclosure without an ID
	}
	c.ids.Add(d.Vulnerability.ID)

	if !cfg.KeepFixVersions && len(d.Vulnerability.Fix.Versions) > 0 {
		d.Vulnerability.Fix = vulnerability.Fix{
			State: vulnerability.FixStateUnknown,
		}
	}

	c.disclosuresByID[d.Vulnerability.ID] = append(c.disclosuresByID[d.Vulnerability.ID], d)
}

func (c *MatchFactory) AddVulnsAsResolutions(vs ...vulnerability.Vulnerability) {
	for _, r := range vulnsToResolution(vs...) {
		if r.ID == "" {
			continue // we cannot add a resolution without an ID
		}
		c.ids.Add(r.ID)
		c.resolutionsByID[r.ID] = append(c.resolutionsByID[r.ID], r)
	}
}

func (c *MatchFactory) Matches() ([]match.Match, error) {
	var matches []match.Match
	for _, a := range c.reconcile() {
		sb := c.assignNamespace(a.Config.MatchDetailPrototype.SearchedBy, a.Vulnerability.Namespace)

		details, p := c.buildMatchDetails(a, sb)

		matches = append(matches, match.Match{
			Vulnerability: a.Vulnerability,
			Package:       p,
			Details:       details,
		})
	}
	return matches, nil
}

func (c *MatchFactory) reconcile() []advisory {
	ids := c.ids.List()
	sort.Strings(ids)

	var advisories []advisory
	for _, id := range ids {
		advisories = append(advisories, c.processVulnerabilityID(id)...)
	}

	return advisories
}

// processVulnerabilityID processes a single vulnerability ID and returns relevant advisories
func (c *MatchFactory) processVulnerabilityID(id string) []advisory {
	ds, ok := c.disclosuresByID[id]
	if len(ds) == 0 || !ok {
		log.WithFields("vulnerability", id).Trace("no disclosures found for vulnerability, skipping")
		return nil
	}

	rs, ok := c.resolutionsByID[id]
	if len(rs) == 0 || !ok {
		// no resolutions found for this vulnerability, so we will include all disclosures
		return ds
	}

	return c.filterDisclosures(ds, rs)
}

// filterDisclosures filters disclosures based on resolutions
func (c *MatchFactory) filterDisclosures(disclosures []advisory, resolutions []resolution) []advisory {
	var filteredAdvisories []advisory

	for _, d := range disclosures {
		finalAdvisory, shouldInclude := c.evaluateDisclosure(d, resolutions)
		if shouldInclude {
			filteredAdvisories = append(filteredAdvisories, finalAdvisory)
		}
	}

	return filteredAdvisories
}

// evaluateDisclosure evaluates a single disclosure against all resolutions
func (c *MatchFactory) evaluateDisclosure(disclosure advisory, resolutions []resolution) (advisory, bool) {
	fixVersions := strset.New()
	var state vulnerability.FixState

	for _, r := range resolutions {
		switch r.Fix.State {
		case vulnerability.FixStateWontFix, vulnerability.FixStateUnknown:
			// these do not negate disclosures, so we will skip them
			continue
		}

		isVulnerable, err := r.Constraint.Satisfied(disclosure.Config.pkgVersion)
		if err != nil {
			log.WithFields("vulnerability", disclosure.Vulnerability.ID, "error", err).Tracef("failed to check constraint for vulnerability")
			continue // skip this resolution, but check other resolutions
		}

		if !isVulnerable {
			// a fix applies to the package, so we're not vulnerable (thus should not keep this disclosure)
			return advisory{}, false
		}

		// we're vulnerable... keep any fix versions that could have been applied
		fixVersions.Add(r.Fix.Versions...)
		if state != vulnerability.FixStateFixed {
			state = r.Fix.State
		}
	}

	if state != vulnerability.FixStateFixed {
		return advisory{}, false
	}

	finalAdvisory := disclosure
	finalAdvisory.Vulnerability.Fix = c.buildFinalFix(fixVersions, state)

	return finalAdvisory, true
}

// buildFinalFix constructs the final fix information from collected versions and state
func (c *MatchFactory) buildFinalFix(fixVersions *strset.Set, state vulnerability.FixState) vulnerability.Fix {
	fixVersions.Remove("")
	fixVersionList := fixVersions.List()
	sort.Strings(fixVersionList)

	return vulnerability.Fix{
		State:    state,
		Versions: fixVersionList,
	}
}

// assignNamespace assigns the vulnerability namespace to the searchedBy parameters
// this is here for legacy reasons: in the past the namespace was input for a search, now it is a hold-over
// that will be removed in the future
func (c *MatchFactory) assignNamespace(searchedBy any, namespace string) any {
	switch v := searchedBy.(type) {
	case match.DistroParameters:
		v.Namespace = namespace
		return v
	case match.CPEParameters:
		v.Namespace = namespace
		return v
	case match.EcosystemParameters:
		v.Namespace = namespace
		return v
	default:
		return searchedBy
	}
}

// buildMatchDetails constructs match details for an advisory
func (c *MatchFactory) buildMatchDetails(a advisory, searchedBy any) ([]match.Detail, pkg.Package) {
	var details []match.Detail

	p := c.pkg
	ty := match.ExactDirectMatch
	if a.Config.MatchDetailPrototype.RefPackage != nil {
		ty = match.ExactIndirectMatch
		p = *a.Config.MatchDetailPrototype.RefPackage
	}

	d := match.Detail{
		Type:       ty,
		Matcher:    a.Config.MatchDetailPrototype.Matcher,
		SearchedBy: searchedBy,
		Confidence: confidenceForMatchType(ty),
	}

	if a.Config.FoundGenerator != nil {
		d.Found = a.Config.FoundGenerator(a.Vulnerability)
	}

	if a.Config.FoundGenerator != nil || len(a.ExistingMatchDetails) == 0 {
		details = append(details, d)
	}

	details = append(details, a.ExistingMatchDetails...)
	return details, p
}

func confidenceForMatchType(mt match.Type) float64 {
	switch mt {
	case match.ExactDirectMatch, match.ExactIndirectMatch:
		return exactMatchConfidence
	case match.CPEMatch:
		return cpeMatchConfidence
	default:
		return defaultConfidence
	}
}

func matchesToDisclosure(cfg *DisclosureConfig, ms ...match.Match) []advisory {
	var out []advisory
	for _, m := range ms {
		out = append(out, advisory{
			Config:               cfg,
			Vulnerability:        m.Vulnerability,
			ExistingMatchDetails: m.Details,
		})
	}
	return out
}

func vulnsToDisclosure(vs ...vulnerability.Vulnerability) []advisory {
	var out []advisory
	for _, v := range vs {
		out = append(out, advisory{Vulnerability: v})
	}
	return out
}

func vulnsToResolution(vs ...vulnerability.Vulnerability) []resolution {
	var out []resolution
	for _, v := range vs {
		if len(v.Fix.Versions) == 0 {
			continue
		}

		constraint := buildFixConstraint(v)
		if constraint == nil {
			continue
		}

		out = append(out, resolution{
			Reference:  v.Reference,
			Fix:        v.Fix,
			Constraint: constraint,
		})
	}
	return out
}

// buildFixConstraint creates a version constraint from fix versions
func buildFixConstraint(v vulnerability.Vulnerability) version.Constraint {
	var constraints []string
	for _, f := range v.Fix.Versions {
		constraints = append(constraints, fmt.Sprintf("< %s", f))
	}

	if len(constraints) == 0 {
		return nil // no fix versions, so no constraint can be built
	}

	constraint, err := version.GetConstraint(strings.Join(constraints, " || "), v.Constraint.Format())
	if err != nil {
		log.WithFields("error", err, "vulnerability", v.String()).Debug("unable to parse fix constraint")
		return nil
	}

	return constraint
}
