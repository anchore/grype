package internal

import (
	"fmt"
	"github.com/anchore/go-logger"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/scylladb/go-set/strset"
	"sort"
	"strings"
)

// Disclosure represents a claim of something being vulnerable.
type Disclosure struct {
	// temporary
	// TODO: we must not include fix info (e.g. alma)
	vulnerability.Vulnerability
}

// Resolution represents the conclusion of a vulnerability being fixed, wont-fixed, or not-fixed, and the specifics thereof.
type Resolution struct {
	// temporary
	vulnerability.Reference
	vulnerability.Fix
	Constraint version.Constraint // TODO: i really don't want this here, but we don't have the format until we expose the data from the fix directly
}

type MatchFactory struct {
	MatchPrototype
	ids             *strset.Set
	disclosuresByID map[string][]Disclosure
	resolutionsByID map[string][]Resolution
}

type MatchPrototype struct {
	Pkg        pkg.Package
	Type       match.Type
	Matcher    match.MatcherType
	SearchedBy any
}

func NewMatchFactory(prototype MatchPrototype) *MatchFactory {
	return &MatchFactory{
		MatchPrototype:  prototype,
		ids:             strset.New(),
		disclosuresByID: make(map[string][]Disclosure),
		resolutionsByID: make(map[string][]Resolution),
	}
}

func (c *MatchFactory) AddDisclosures(vs ...vulnerability.Vulnerability) {
	for _, d := range toDisclosures(vs...) {
		if d.ID == "" {
			return // we cannot add a disclosure without an ID
		}
		c.ids.Add(d.ID)
		if existing, ok := c.disclosuresByID[d.ID]; ok {
			c.disclosuresByID[d.ID] = append(existing, d)
		} else {
			c.disclosuresByID[d.ID] = []Disclosure{d}
		}
	}
}

func (c *MatchFactory) AddResolutions(vs ...vulnerability.Vulnerability) {
	for _, r := range toResolutions(vs...) {
		if r.ID == "" {
			return // we cannot add a resolution without an ID
		}
		c.ids.Add(r.ID)
		if existing, ok := c.resolutionsByID[r.ID]; ok {
			c.resolutionsByID[r.ID] = append(existing, r)
		} else {
			c.resolutionsByID[r.ID] = []Resolution{r}
		}
	}
}

func (c *MatchFactory) Reconcile() ([]vulnerability.Vulnerability, error) {
	ids := c.ids.List()
	sort.Strings(ids)

	p := c.MatchPrototype.Pkg
	verObj := version.NewVersionFromPkg(p)

	var vulns []vulnerability.Vulnerability
vulnLoop:
	for _, id := range ids {
		ds, ok := c.disclosuresByID[id]
		if len(ds) == 0 || !ok {
			log.WithFields(logger.Fields{
				"vulnerability": id,
			}).Trace("no disclosures found for vulnerability, skipping")
			continue vulnLoop
		}

		rs, ok := c.resolutionsByID[id]
		if len(rs) == 0 || !ok {
			// no resolutions found for this vulnerability, so we will not include it
			for _, d := range ds {
				vulns = append(vulns, d.Vulnerability)
			}
			continue vulnLoop
		}

		// keep only the disclosures that match the criteria of the resolution
	disclosureLoop:
		for _, d := range ds {
			fixVersions := strset.New()
			var state vulnerability.FixState
			for _, r := range rs {
				switch r.Fix.State {
				case vulnerability.FixStateWontFix, vulnerability.FixStateUnknown:
					// these do not negate disclosures, so we will skip them
					continue
				}
				isVulnerable, err := r.Constraint.Satisfied(verObj)
				if err != nil {
					log.WithFields(logger.Fields{
						"vulnerability": d.ID,
						"error":         err,
					}).Tracef("failed to check constraint for vulnerability")
					continue // skip this resolution, but check other resolutions
				}
				if !isVulnerable {
					// a fix applies to the package, so we're not vulnerable (thus should not keep this disclosure)
					// TODO: in the future raise up evidence of this
					continue disclosureLoop
				}
				// we're vulnerable! keep any fix versions that could have been applied

				fixVersions.Add(r.Fix.Versions...)
				if state != vulnerability.FixStateFixed {
					state = r.Fix.State
				}
			}

			if state != vulnerability.FixStateFixed {
				// TODO: this needs to get rethought as we come up with more reasons here (e.g. not applicable, not vulnerable, etc.)
				continue
			}

			vuln := d.Vulnerability

			fixVersions.Remove("")
			fixVersionList := fixVersions.List()
			sort.Strings(fixVersionList) // TODO: use version sort, not lexically... this is in the vulnerability package today

			vuln.Fix.State = state
			vuln.Fix.Versions = fixVersionList

			// this disclosure does not have a resolution that satisfies it, so we will keep it... patching on any fixes that we are aware of
			vulns = append(vulns, vuln)
		}

		// TODO: in the future we should save evidence of being ignored here
	}

	return vulns, nil
}

func (c *MatchFactory) Matches(found func(vulnerability.Vulnerability) any) ([]match.Match, error) {
	vulns, err := c.Reconcile()
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile vulnerabilities: %w", err)
	}

	var matches []match.Match
	for _, vuln := range vulns {
		sb := c.MatchPrototype.SearchedBy
		switch v := sb.(type) {
		case match.DistroParameters:
			v.Namespace = vuln.Namespace
			sb = v
		}

		detail := match.Detail{
			Type:       c.MatchPrototype.Type,
			Matcher:    c.MatchPrototype.Matcher,
			SearchedBy: sb,
			Found:      found(vuln),
			Confidence: confidenceForMatchType(c.MatchPrototype.Type),
		}

		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       c.MatchPrototype.Pkg,
			Details:       []match.Detail{detail},
		})
	}
	return matches, nil
}

func confidenceForMatchType(mt match.Type) float64 {
	switch mt {
	case match.ExactDirectMatch, match.ExactIndirectMatch:
		return 1.0 // TODO: this is hard coded for now
	case match.CPEMatch:
		return 0.9 // TODO: this is hard coded for now
	default:
		return 0.0
	}
}

func toDisclosures(vs ...vulnerability.Vulnerability) []Disclosure {
	// temporary
	var out []Disclosure
	for _, v := range vs {
		// TODO: should we remove the fix info?
		out = append(out, Disclosure{Vulnerability: v})
	}
	return out
}

func toResolutions(vs ...vulnerability.Vulnerability) []Resolution {
	// temporary
	var out []Resolution
	for _, v := range vs {
		if len(v.Fix.Versions) == 0 {
			continue
		}
		var constraints []string
		for _, f := range v.Fix.Versions {
			constraints = append(constraints, fmt.Sprintf("< %s", f))
		}

		constraint, err := version.GetConstraint(strings.Join(constraints, " || "), v.Constraint.Format())
		if err != nil {
			log.WithFields("error", err, "vulnerability", v.String()).Debug("unable to parse fix constraint")
			continue // skip this resolution
		}

		out = append(out, Resolution{
			Reference:  v.Reference,
			Fix:        v.Fix,
			Constraint: constraint, // TODO: not great, but is actionable based on the fix
		})
	}
	return out
}
