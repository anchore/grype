package result

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/scylladb/go-set/strset"
)

// Result represents a prototype match of a package used to search, a set of vulnerabilities discovered from the search,
// and match details that describe the search itself. Note that all vulnerabilities in a Result share the same
// vulnerability ID (in the ID field and `.Vulnerabilities[].ID` fields -- it is invalid to mix vulnerabilities into
// a Result that have different IDs.
type Result struct {
	// ID is the vulnerability ID; all vulnerabilities in this Result share the same ID.
	ID string

	// Vulnerabilities is a set of vulnerabilities that were discovered from the search.
	Vulnerabilities []vulnerability.Vulnerability

	// Details is a set of match details that describe the search itself
	Details []match.Detail

	// Package is the package that was used to search for vulnerabilities.
	Package *pkg.Package
}

type Set map[string][]Result

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
	merged.Details = NewMatchDetailsSet(merged.Details...).ToSlice()
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

// Remove will prune elements from the current set that have any ids/aliases in common with the incoming set.
// For example:
//
// set 1:
//
//	Entry A: GHSA-g4mx-q9vg-27p4  (alias CVE-2023-45803)
//
// set 2:
//
//	Entry B: CGA-7qjw-ggh3-pp9f (alias CVE-2023-45803)
//
// We want to be able to remove Entry A from set 1 because it has the same alias as Entry B in set 2.
// This is because the vulnerability IDs are different, but they refer to the same underlying vulnerability.
func (s Set) Remove(incoming Set) Set {
	out := Set{}

	incomingIDsByAliases := map[string]*strset.Set{}
	for id, results := range incoming {
		for _, alias := range extractAliases(results).List() {
			if _, ok := incomingIDsByAliases[alias]; !ok {
				incomingIDsByAliases[alias] = strset.New()
			}
			incomingIDsByAliases[alias].Add(id)
		}
	}

	for id, results := range s {
		// remove if incoming set contains the same ID directly
		if incoming.Contains(id) {
			continue
		}
		// remove if this entry's ID appears as an alias in the incoming set
		if _, ok := incomingIDsByAliases[id]; ok {
			continue
		}
		// remove if any of this entry's aliases overlap with incoming aliases
		currentAliases := extractAliases(results).List()
		for _, alias := range currentAliases {
			if _, ok := incomingIDsByAliases[alias]; ok {
				goto remove
			}
		}
		out[id] = results
		continue
		remove:
	}
	return out
}

func extractAliases(results []Result) *strset.Set {
	aliases := strset.New()
	for _, r := range results {
		for _, v := range r.Vulnerabilities {
			for _, a := range v.RelatedVulnerabilities {
				aliases.Add(a.ID)
			}
		}
	}
	return aliases
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
	allIDs := make(map[string]struct{})
	for id := range s {
		allIDs[id] = struct{}{}
	}
	for id := range incoming {
		allIDs[id] = struct{}{}
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
			for _, result := range mergedResults {
				if result.ID != "" && len(result.Vulnerabilities) > 0 {
					out[result.ID] = append(out[result.ID], result)
				}
			}
		}
	}

	return out
}

func (s Set) Contains(id string) bool {
	results, ok := s[id]
	return ok && len(results) > 0
}

func (s Set) ContainsAny(ids ...string) bool {
	for _, id := range ids {
		results, ok := s[id]
		if ok && len(results) > 0 {
			return true
		}
	}
	return false
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
		} else if len(results) > 0 {
			vulnerability.LogDropped(id, "filterVulns", "no vulnerabilities matched criteria", criteria)
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
