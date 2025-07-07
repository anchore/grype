package result

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

type Result struct {
	ID              ID
	Vulnerabilities []vulnerability.Vulnerability
	Details         []match.Detail
	Package         *pkg.Package
}

type ID string

type Set map[ID][]Result

func unionIntoResult(existing []Result) Result {
	var merged Result
	for _, r := range existing {
		if merged.ID == "" {
			merged.ID = r.ID
			merged.Package = r.Package
		}
		merged.Vulnerabilities = append(merged.Vulnerabilities, r.Vulnerabilities...)
		merged.Details = append(merged.Details, r.Details...)
	}
	merged.Details = internal.NewMatchDetailsSet(merged.Details...).ToSlice()
	return merged
}

func (s Set) ToMatches() []match.Match {
	var out []match.Match
	for _, results := range s {
		merged := unionIntoResult(results)

		if len(merged.Vulnerabilities) == 0 {
			continue
		}

		if merged.Package == nil {
			continue // skip results without a package
		}

		for _, vv := range merged.Vulnerabilities {
			out = append(out,
				match.Match{
					Vulnerability: vv,
					Package:       *merged.Package,
					Details:       merged.Details,
				},
			)
		}
	}

	return out
}

func (s Set) Remove(incoming Set) Set {
	out := Set{}
	for id, results := range s {
		if incoming.Contains(id) {
			continue
		}
		out[id] = results
	}
	return out
}

func unionResults(existing, incoming []Result) (n []Result) {
	n = append(n, existing...)
	n = append(n, incoming...)
	return n
}

func (s Set) Merge(incoming Set, mergeFuncs ...func(existing, incoming []Result) []Result) Set {
	out := Set{}
	if len(mergeFuncs) == 0 {
		// with no other merge functions specified, append all vulnerability results and details
		mergeFuncs = []func(existing, incoming []Result) []Result{
			unionResults,
		}
	}

	// det all unique IDs from both sets
	allIDs := make(map[ID]bool)
	for id := range s {
		allIDs[id] = true
	}
	for id := range incoming {
		allIDs[id] = true
	}

	// process each ID, applying all merge functions
	for id := range allIDs {
		existingResults := s[id]
		incomingResults := incoming[id]

		mergedResults := append([]Result(nil), existingResults...)
		for _, mergeFunc := range mergeFuncs {
			mergedResults = mergeFunc(mergedResults, incomingResults)
		}

		if len(mergedResults) > 0 {
			// filter out any results with empty vulnerabilities
			var validResults []Result
			for _, result := range mergedResults {
				if result.ID != "" && len(result.Vulnerabilities) > 0 {
					validResults = append(validResults, result)
				}
			}
			if len(validResults) > 0 {
				out[id] = validResults
			}
		}
	}

	return out
}

func (s Set) Contains(id ID) bool {
	results, ok := s[id]
	return ok && len(results) > 0
}

func (s Set) Filter(criteria ...vulnerability.Criteria) Set {
	out := Set{}
	for id, results := range s {
		var filteredResults []Result

		for _, result := range results {
			vulns, err := filterVulns(result.Vulnerabilities, criteria)
			if err != nil {
				log.WithFields("vulnerability", result.ID, "error", err).Debug("failed to filter vulns")
				// if there was an error filtering vulnerabilities, keep them all
				vulns = result.Vulnerabilities
			}
			if len(vulns) == 0 {
				continue
			}

			filteredResults = append(filteredResults, Result{
				ID:              result.ID,
				Vulnerabilities: vulns,
				Details:         result.Details,
			})
		}

		if len(filteredResults) > 0 {
			out[id] = filteredResults
		}
	}
	return out
}

func filterVulns(vulnerabilities []vulnerability.Vulnerability, criteria []vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	var out []vulnerability.Vulnerability
nextVulnerability:
	for _, v := range vulnerabilities {
		for _, c := range criteria {
			matches, dropReason, err := c.MatchesVulnerability(v)
			if err != nil {
				return nil, err
			}
			if !matches {
				vulnerability.LogDropped(v.ID, "filterVulns", dropReason, c)
				continue nextVulnerability
			}
		}
		out = append(out, v)
	}
	return out, nil
}
