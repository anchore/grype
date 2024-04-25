package csaf

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	vexStatus "github.com/anchore/grype/grype/vex/status"

	"github.com/aws/smithy-go/time"
	"github.com/csaf-poc/csaf_distribution/v3/csaf"
)

// searchedBy captures the parameters used to search through the VEX data
type searchedBy struct {
	Vulnerability string
	Purl          string
}

type Processor struct{}

func New() *Processor {
	return &Processor{}
}

// IsCSAF checks if the provided document is a CSAF document
func IsCSAF(document string) bool {
	if _, err := csaf.LoadAdvisory(document); err == nil {
		return true
	}
	return false
}

// ReadVexDocuments reads different files and creates a collection of advisories based on them.
func (*Processor) ReadVexDocuments(docs []string) (interface{}, error) {
	var advs advisories

	for _, doc := range docs {
		adv, err := csaf.LoadAdvisory(doc)
		if err != nil {
			return nil, fmt.Errorf("error loading VEX CSAF document: %w", err)
		}
		advs = append(advs, adv)
	}

	// The collection is sorted by date, so newer advisories are guaranteed to be consumed before.
	sort.SliceStable(advs, func(i, j int) bool {
		i_t, _ := time.ParseDateTime(*advs[i].Document.Tracking.CurrentReleaseDate)
		j_t, _ := time.ParseDateTime(*advs[j].Document.Tracking.CurrentReleaseDate)
		return i_t.Before(j_t)
	})

	return advs, nil
}

// FilterMatches takes a set of scanning results and moves any results marked in
// the VEX data as fixed or not_affected to the ignored list.
func (*Processor) FilterMatches(
	docRaw interface{}, ignoreRules []match.IgnoreRule, _ *pkg.Context, matches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {

	advisories, ok := docRaw.(advisories)
	if !ok {
		return nil, nil, errors.New("unable to cast vex document as CSAF Advisories")
	}

	remainingMatches := match.NewMatches()
	for _, m := range matches.Sorted() {
		// Seek if our advisories have information about a vulnerability affecting
		// the product for which we have a match.
		advMatch := advisories.matches(m.Vulnerability.ID, m.Package.PURL)
		if advMatch == nil {
			remainingMatches.Add(m)
			continue
		}

		// Filtering only applies to not_affected and fixed statuses
		if !matchesVexStatus(advMatch.Status, vexStatus.NotAffected) && !matchesVexStatus(advMatch.Status, vexStatus.Fixed) {
			remainingMatches.Add(m)
			continue
		}

		// Check if there's any ignore rule that matches the current match statement
		rule := matchingRule(ignoreRules, m, advMatch, vexStatus.IgnoreList())
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
// are moved from the ignore list or synthesized when no previous data is found.
func (*Processor) AugmentMatches(
	docRaw interface{}, ignoreRules []match.IgnoreRule, _ *pkg.Context, matches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {

	advisories, ok := docRaw.(advisories)
	if !ok {
		return nil, nil, errors.New("unable to cast vex document as CSAF Advisories")
	}

	remainingIgnoredMatches := []match.IgnoredMatch{}
	for _, m := range ignoredMatches {
		if advMatch := advisories.matches(m.Vulnerability.ID, m.Package.PURL); advMatch != nil {
			if rule := matchingRule(ignoreRules, m.Match, advMatch, vexStatus.AugmentList()); rule != nil {
				newMatch := m.Match
				newMatch.Details = append(newMatch.Details, match.Detail{
					Type: match.ExactDirectMatch,
					SearchedBy: &searchedBy{
						Vulnerability: m.Vulnerability.ID,
						Purl:          m.Package.PURL,
					},
					Found:   advMatch,
					Matcher: match.CsafVexMatcher,
				})
				matches.Add(newMatch)
				continue
			}
		}

		remainingIgnoredMatches = append(remainingIgnoredMatches, m)
	}

	return matches, remainingIgnoredMatches, nil
}

// matchingRule cycles through a set of ignore rules and returns the first
// one that matches the statement and the match. Returns nil if none match.
func matchingRule(ignoreRules []match.IgnoreRule, m match.Match, advMatch *advisoryMatch, allowedStatuses []vexStatus.Status) *match.IgnoreRule {
	ms := match.NewMatches()
	ms.Add(m)

	// By default, if there are no ignore rules (which means the user didn't provide
	// any custom VEX rule), a matching rule should be returned if the advisory
	// match status is one of the allowed statuses.
	if len(ignoreRules) == 0 {
		for _, status := range allowedStatuses {
			if matchesVexStatus(advMatch.Status, status) {
				return &match.IgnoreRule{
					Namespace:        "vex",
					Vulnerability:    advMatch.cve(),
					VexJustification: advMatch.statement(),
					VexStatus:        string(status),
				}
			}
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

		// If the advisory match status is not the same as the rule status,
		// it does not apply
		if !matchesVexStatus(advMatch.Status, vexStatus.Status(rule.VexStatus)) {
			continue
		}

		// If the rule has a status other than the allowed ones, skip:
		if rule.VexStatus != "" && !slices.Contains(allowedStatuses, vexStatus.Status(rule.VexStatus)) {
			continue
		}

		// If the vulnerability is blank in the rule it means we will honor
		// any status with any vulnerability. Alternatively, if the vulnerability
		// is set, the rule applies if it is the same in the advisory match and the rule.
		if rule.Vulnerability == "" || advMatch.cve() == rule.Vulnerability {
			return &rule
		}

		// If the rule applies to a VEX justification it needs to match the
		// advisory match statement, note that justifications only apply to not_affected:
		if matchesVexStatus(advMatch.Status, vexStatus.NotAffected) && rule.VexJustification != "" &&
			rule.VexJustification != advMatch.statement() {
			continue
		}

		if advMatch.cve() == rule.Vulnerability {
			return &rule
		}
	}

	return nil
}
