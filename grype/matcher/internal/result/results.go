package result

import (
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// Result represents a prototype match of a package used to search, a set of vulnerabilities discovered from the search,
// and match details that describe the search itself. Note that all vulnerabilities in a Result share the same
// vulnerability ID (in the ID field and `.Vulnerabilities[].ID` fields -- it is invalid to mix vulnerabilities into
// a Result that have different IDs.
type Result struct {
	vulnerability.Vulnerability
	Criteria []vulnerability.Criteria
}

type Set map[string][]Result

func (s Set) Remove(incoming Set) Set {
	out := Set{}
	for id, results := range s {
		if incoming.Contains(id) {
			vulnerability.LogDropped(id, "remove", "in remove set", nil)
			continue
		}
		out[id] = results
	}
	return out
}

func (s Set) Keep(incoming Set) Set {
	out := Set{}
	for id, results := range s {
		if !incoming.Contains(id) {
			vulnerability.LogDropped(id, "keep", "not in kept set", nil)
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

		if len(mergedResults) == 0 {
			// this result is filtered out as part of the merge operation
			vulnerability.LogDropped(id, "merge", "dropped", nil)
			continue
		}

		out.appendResults(mergedResults...)
	}

	return out
}

func (s Set) Contains(id string) bool {
	results, ok := s[id]
	return ok && len(results) > 0
}

func (s Set) Filter(criteria ...vulnerability.Criteria) Set {
	return s.FilterFunc(func(results []Result) ([]Result, error) {
		return filterResults(results, criteria)
	})
}

func (s Set) FilterFunc(filterFunc func(result []Result) ([]Result, error)) Set {
	out := Set{}
	for id, existing := range s {
		result, err := filterFunc(existing)
		if err != nil {
			log.WithFields("vulnerability", id, "error", err).Debug("failed to filter vulns")
			// if there was an error filtering vulnerabilities, keep them all
			result = existing
		}
		if len(result) == 0 {
			vulnerability.LogDropped(id, "filter", "not kept", filterFunc)
			continue
		}
		out.appendResults(result...)
	}
	return out
}

func (s Set) appendResults(results ...Result) {
	for _, result := range results {
		if result.ID == "" {
			vulnerability.LogDropped(result.Namespace, "appendResults", "no ID", result)
			return
		}
		// always use the ID returned on the filtered record, this could be changed, for example, if
		// a "reorient by CVE" operation occurs and transitions a GHSA record to a corresponding CVE record
		s[result.ID] = append(s[result.ID], result)
	}
}

func filterResults(results []Result, criteria []vulnerability.Criteria) ([]Result, error) {
	var out []Result
nextVulnerability:
	for _, r := range results {
		for _, c := range criteria {
			matches, dropReason, err := c.MatchesVulnerability(r.Vulnerability)
			if err != nil {
				return nil, err
			}
			if !matches {
				vulnerability.LogDropped(r.ID, "filterVulns", dropReason, c)
				continue nextVulnerability
			}
		}
		r.Criteria = append(r.Criteria, criteria...)
		out = append(out, r)
	}
	return out, nil
}
