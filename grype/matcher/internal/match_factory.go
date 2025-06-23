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
	config *DisclosureConfig // the config used to create this disclosure, which contains the prototype and other information
	vulnerability.Vulnerability

	matchDetails []match.Detail
}

// TODO: this would be a combination of the disclosure and resolution... which is already on vulnerability.Vulnerability
// so in the future this would be a more sane definition
type advisory Disclosure

// Resolution represents the conclusion of a vulnerability being fixed, wont-fixed, or not-fixed, and the specifics thereof.
type Resolution struct {
	// temporary
	//config *ResolutionConfig // the config used to create this resolution, which contains the prototype and other information
	vulnerability.Reference
	vulnerability.Fix
	Constraint version.Constraint // TODO: i really don't want this here, but we don't have the format until we expose the data from the fix directly
}

type MatchFactory struct {
	ids             *strset.Set
	pkg             pkg.Package // the package that is being matched against
	disclosuresByID map[string][]Disclosure
	resolutionsByID map[string][]Resolution
}

type MatchPrototype struct {
	version *version.Version // the version of the package that was matched

	Type       match.Type
	Matcher    match.MatcherType
	SearchedBy any
}

type DisclosureConfig struct {
	KeepFixVersions  bool                                  // whether to remove fix information from the disclosures
	FoundByGenerator func(vulnerability.Vulnerability) any // a function that returns the "found by" information for the disclosure
	MatchPrototype   MatchPrototype
}

//type ResolutionConfig struct {
//	IgnoreRuleGenerator func(pkg.Package, vulnerability.Vulnerability) []match.IgnoreFilter // a function that returns the "ignore rule" for the resolution
//}

func NewMatchFactory(p pkg.Package) *MatchFactory {
	return &MatchFactory{
		pkg:             p,
		ids:             strset.New(),
		disclosuresByID: make(map[string][]Disclosure),
		resolutionsByID: make(map[string][]Resolution),
	}
}

func (c *MatchFactory) AddMatchesAsDisclosuresFromMatches(cfg DisclosureConfig, ms ...match.Match) {
	for _, d := range matchesToDisclosure(&cfg, ms...) {
		c.addDisclosure(&cfg, d)
	}
}

func (c *MatchFactory) AddVulnsAsDisclosures(cfg DisclosureConfig, vs ...vulnerability.Vulnerability) {
	for _, d := range vulnsToDisclosure(vs...) {
		c.addDisclosure(&cfg, d)
	}
}

func (c *MatchFactory) addDisclosure(cfg *DisclosureConfig, d Disclosure) {
	cfg.MatchPrototype.version = version.NewVersionFromPkg(c.pkg)
	d.config = cfg

	if d.ID == "" {
		return // we cannot add a disclosure without an ID
	}
	c.ids.Add(d.ID)

	if !cfg.KeepFixVersions && len(d.Vulnerability.Fix.Versions) > 0 {
		d.Vulnerability.Fix = vulnerability.Fix{
			State: vulnerability.FixStateUnknown,
		}
	}

	if existing, ok := c.disclosuresByID[d.ID]; ok {
		c.disclosuresByID[d.ID] = append(existing, d)
	} else {
		c.disclosuresByID[d.ID] = []Disclosure{d}
	}
}

func (c *MatchFactory) AddVulnsAsResolutions(vs ...vulnerability.Vulnerability) {
	for _, r := range vulnsToResolution(vs...) {
		if r.ID == "" {
			return // we cannot add a resolution without an ID
		}
		c.ids.Add(r.ID)
		//r.config = &cfg
		if existing, ok := c.resolutionsByID[r.ID]; ok {
			c.resolutionsByID[r.ID] = append(existing, r)
		} else {
			c.resolutionsByID[r.ID] = []Resolution{r}
		}
	}
}

func (c *MatchFactory) reconcile() ([]advisory, []match.IgnoreFilter, error) {
	ids := c.ids.List()
	sort.Strings(ids)

	var vulns []Disclosure
	var ignored []match.IgnoreFilter
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
				vulns = append(vulns, d)
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
				isVulnerable, err := r.Constraint.Satisfied(d.config.MatchPrototype.version)
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

			vuln := d

			fixVersions.Remove("")
			fixVersionList := fixVersions.List()
			sort.Strings(fixVersionList) // TODO: use version sort, not lexically... or does this matter... when converting to a model for presentation this will be handled.

			vuln.Fix.State = state
			vuln.Fix.Versions = fixVersionList

			// this disclosure does not have a resolution that satisfies it, so we will keep it... patching on any fixes that we are aware of
			vulns = append(vulns, vuln)
		}

		// TODO: in the future we should save evidence of being ignored here
	}

	// TODO: temp glue code
	var ads []advisory
	for _, d := range vulns {
		ads = append(ads, advisory(d))
	}

	return ads, ignored, nil
}

func (c *MatchFactory) Matches() ([]match.Match, []match.IgnoreFilter, error) {
	advisories, ignored, err := c.reconcile()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to reconcile vulnerabilities: %w", err)
	}

	var matches []match.Match
	for _, a := range advisories {
		sb := a.config.MatchPrototype.SearchedBy
		switch v := sb.(type) {
		case match.DistroParameters:
			v.Namespace = a.Namespace
			sb = v
		}

		var details []match.Detail
		if a.config.FoundByGenerator != nil {
			// TODO: should we have a default FoundByGenerator?
			details = []match.Detail{
				{
					Type:       a.config.MatchPrototype.Type,
					Matcher:    a.config.MatchPrototype.Matcher,
					SearchedBy: sb,
					Found:      a.config.FoundByGenerator(a.Vulnerability),
					Confidence: confidenceForMatchType(a.config.MatchPrototype.Type),
				},
			}
		}

		details = append(details, a.matchDetails...)

		matches = append(matches, match.Match{
			Vulnerability: a.Vulnerability,
			Package:       c.pkg,
			Details:       details,
		})
	}
	return matches, ignored, nil
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

func matchesToDisclosure(cfg *DisclosureConfig, ms ...match.Match) []Disclosure {
	var out []Disclosure
	for _, m := range ms {
		out = append(out, Disclosure{
			config:        cfg,
			Vulnerability: m.Vulnerability,
			matchDetails:  m.Details,
		})
	}
	return out
}

func vulnsToDisclosure(vs ...vulnerability.Vulnerability) []Disclosure {
	// temporary
	var out []Disclosure
	for _, v := range vs {
		// TODO: should we remove the fix info?
		out = append(out, Disclosure{Vulnerability: v})
	}
	return out
}

func vulnsToResolution(vs ...vulnerability.Vulnerability) []Resolution {
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
