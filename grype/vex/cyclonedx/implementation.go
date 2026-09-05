package cyclonedx

import (
	"errors"
	"fmt"
	"os"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	vexStatus "github.com/anchore/grype/grype/vex/status"
)

type Processor struct{}

func New() *Processor {
	return &Processor{}
}

// Match captures the criteria that caused a vulnerability to match a CycloneDX VEX document
type Match struct {
	Vulnerability cdx.Vulnerability
}

// SearchedBy captures the parameters used to search through the VEX data
type SearchedBy struct {
	Vulnerability string
}

// IsCycloneDX checks if the provided document is a CycloneDX document
func IsCycloneDX(document string) bool {
	f, err := os.Open(document)
	if err != nil {
		return false
	}
	defer f.Close()

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err == nil && bom.BOMFormat == cdx.BOMFormat {
		return true
	}
	return false
}

// ReadVexDocuments reads CycloneDX BOM documents and returns a collection of BOMs
func (p *Processor) ReadVexDocuments(docs []string) (any, error) {
	var boms []*cdx.BOM

	for _, doc := range docs {
		f, err := os.Open(doc)
		if err != nil {
			return nil, fmt.Errorf("opening CycloneDX VEX document %q: %w", doc, err)
		}
		defer f.Close()

		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON)
		if err := decoder.Decode(bom); err != nil {
			return nil, fmt.Errorf("decoding CycloneDX VEX document %q: %w", doc, err)
		}

		boms = append(boms, bom)
	}

	return boms, nil
}

// FilterMatches takes a set of scanning results and moves any results marked in
// the VEX data as fixed or not_affected to the ignored list.
func (p *Processor) FilterMatches(
	docRaw any, ignoreRules []match.IgnoreRule, _ *pkg.Context, matches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {
	boms, ok := docRaw.([]*cdx.BOM)
	if !ok {
		return nil, nil, errors.New("unable to cast vex document as CycloneDX BOMs")
	}

	remainingMatches := match.NewMatches()

	for _, m := range matches.Sorted() {
		vuln := findMatchingVulnerability(boms, m.Vulnerability.ID)
		if vuln == nil {
			remainingMatches.Add(m)
			continue
		}

		state := analysisState(vuln)

		// Filtering only applies to not_affected and fixed (resolved) statuses
		if state != vexStatus.NotAffected && state != vexStatus.Fixed {
			remainingMatches.Add(m)
			continue
		}

		rule := matchingRule(ignoreRules, m, vuln, state, vexStatus.IgnoreList())
		if rule == nil {
			remainingMatches.Add(m)
			continue
		}

		ignoredMatches = append(ignoredMatches, match.IgnoredMatch{
			Match:              m,
			AppliedIgnoreRules: []match.IgnoreRule{*rule},
		})
	}

	return &remainingMatches, ignoredMatches, nil
}

// AugmentMatches adds results to the match.Matches array when matching data
// about an affected VEX product is found on loaded VEX documents. Matches
// are moved from the ignore list back to active matches.
func (p *Processor) AugmentMatches(
	docRaw any, ignoreRules []match.IgnoreRule, _ *pkg.Context, matches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {
	boms, ok := docRaw.([]*cdx.BOM)
	if !ok {
		return nil, nil, errors.New("unable to cast vex document as CycloneDX BOMs")
	}

	remainingIgnoredMatches := []match.IgnoredMatch{}

	for _, m := range ignoredMatches {
		vuln := findMatchingVulnerability(boms, m.Vulnerability.ID)
		if vuln == nil {
			remainingIgnoredMatches = append(remainingIgnoredMatches, m)
			continue
		}

		state := analysisState(vuln)

		// Only augment for affected or under_investigation statuses
		if state != vexStatus.Affected && state != vexStatus.UnderInvestigation {
			remainingIgnoredMatches = append(remainingIgnoredMatches, m)
			continue
		}

		rule := matchingRule(ignoreRules, m.Match, vuln, state, vexStatus.AugmentList())
		if rule == nil {
			remainingIgnoredMatches = append(remainingIgnoredMatches, m)
			continue
		}

		newMatch := m.Match
		newMatch.Details = append(newMatch.Details, match.Detail{
			Type: match.ExactDirectMatch,
			SearchedBy: &SearchedBy{
				Vulnerability: m.Vulnerability.ID,
			},
			Found:   Match{Vulnerability: *vuln},
			Matcher: match.CycloneDXVexMatcher,
		})
		matches.Add(newMatch)
	}

	return matches, remainingIgnoredMatches, nil
}

// findMatchingVulnerability searches through the provided BOMs for a vulnerability
// matching the given CVE ID. Returns the first matching vulnerability, or nil if
// none is found.
func findMatchingVulnerability(boms []*cdx.BOM, vulnID string) *cdx.Vulnerability {
	for _, bom := range boms {
		if bom.Vulnerabilities == nil {
			continue
		}
		for i := range *bom.Vulnerabilities {
			vuln := &(*bom.Vulnerabilities)[i]
			if vuln.ID == vulnID {
				return vuln
			}
		}
	}
	return nil
}

// analysisState maps a CycloneDX vulnerability's analysis state to the canonical VEX status.
func analysisState(vuln *cdx.Vulnerability) vexStatus.Status {
	if vuln.Analysis == nil {
		return ""
	}
	switch vuln.Analysis.State {
	case cdx.IASNotAffected:

		return vexStatus.NotAffected
	case cdx.IASResolved, cdx.IASResolvedWithPedigree:
		return vexStatus.Fixed
	case cdx.IASExploitable:
		return vexStatus.Affected
	case cdx.IASInTriage:
		return vexStatus.UnderInvestigation
	default:
		return ""
	}
}

// matchingRule cycles through a set of ignore rules and returns the first
// one that matches the vulnerability and the match. Returns nil if none match.
func matchingRule(ignoreRules []match.IgnoreRule, m match.Match, vuln *cdx.Vulnerability, state vexStatus.Status, allowedStatuses []vexStatus.Status) *match.IgnoreRule {
	ms := match.NewMatches()
	ms.Add(m)

	// By default, if there are no ignore rules (which means the user didn't provide
	// any custom VEX rule), a matching rule should be returned if the state
	// is one of the allowed statuses.
	if len(ignoreRules) == 0 && slices.Contains(allowedStatuses, state) {
		justification := ""
		if vuln.Analysis != nil {
			justification = string(vuln.Analysis.Justification)
		}
		return &match.IgnoreRule{
			Namespace:        "vex",
			Vulnerability:    vuln.ID,
			VexJustification: justification,
			VexStatus:        string(state),
		}
	}

	for _, rule := range ignoreRules {
		// If the rule has more conditions than just the VEX statement, check if
		// it applies to the current match.
		if rule.HasConditions() {
			r := rule
			r.VexStatus = ""
			if _, ignored := match.ApplyIgnoreRules(ms, []match.IgnoreRule{r}); len(ignored) == 0 {
				continue
			}
		}

		// If the state is not the same as the rule status, it does not apply
		if string(state) != rule.VexStatus {
			continue
		}

		// If the rule has a status other than the allowed ones, skip
		if rule.VexStatus != "" && !slices.Contains(allowedStatuses, vexStatus.Status(rule.VexStatus)) {
			continue
		}

		// If the rule applies to a VEX justification it needs to match,
		// note that justifications only apply to not_affected
		if state == vexStatus.NotAffected && rule.VexJustification != "" &&
			vuln.Analysis != nil && rule.VexJustification != string(vuln.Analysis.Justification) {
			continue
		}

		// If the vulnerability is blank in the rule it means we will honor
		// any status with any vulnerability.
		if rule.Vulnerability == "" {
			return &rule
		}

		// If the vulnerability is set, the rule applies if it matches.
		if rule.Vulnerability == vuln.ID {
			return &rule
		}
	}
	return nil
}
