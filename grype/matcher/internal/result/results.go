package result

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

type Result struct {
	ID              ID
	Vulnerabilities []vulnerability.Vulnerability
	Details         match.Details
}

type ID string

type Set map[ID]Result

func (r Set) ToMatches(p pkg.Package, mergeFuncs ...func(vulns []vulnerability.Vulnerability) []vulnerability.Vulnerability) []match.Match {
	var out []match.Match
	for _, v := range r {
		vulns := v.Vulnerabilities
		if len(mergeFuncs) > 0 {
			// merge vulnerabilities if requested
			for _, mergeFunc := range mergeFuncs {
				vulns = mergeFunc(vulns)
			}
		}

		if len(vulns) == 0 {
			continue
		}

		for _, vv := range vulns {
			out = append(out,
				match.Match{
					Vulnerability: vv,
					Package:       p,
					Details:       v.Details,
				},
			)
		}
	}

	// sort.Sort(match.ByElements(out))
	return out
}

func (r Set) Remove(incoming Set) Set {
	out := Set{}
	for id, v := range r {
		if incoming.Contains(id) {
			continue
		}
		out[id] = v
	}
	return out
}

func defaultResultMerge(existing, incoming Result) Result {
	id := existing.ID
	if id == "" {
		id = incoming.ID
	}
	return Result{
		ID:              id,
		Vulnerabilities: append(existing.Vulnerabilities, incoming.Vulnerabilities...),
		Details:         append(existing.Details, incoming.Details...),
	}
}

var defaultMergeFuncs = []func(existing, incoming Result) Result{
	defaultResultMerge,
}

func (r Set) Merge(incoming Set, mergeFuncs ...func(existing, incoming Result) Result) Set {
	out := Set{}
	if len(mergeFuncs) == 0 {
		// with no other merge functions specified, append all vulnerability results and details
		mergeFuncs = defaultMergeFuncs
	}

	// keep entries from the incoming set, merging with existing entries
nextIncoming:
	for _, v := range incoming {
		newEntry := v
		for _, mergeFunc := range mergeFuncs {
			newEntry = mergeFunc(r[v.ID], newEntry)
			if newEntry.ID == "" || len(newEntry.Vulnerabilities) == 0 {
				continue nextIncoming
			}
		}
		out[v.ID] = newEntry
	}

	// keep entries not present in the incoming set
nextExisting:
	for _, v := range r {
		// skip entries already merged
		if incoming.Contains(v.ID) {
			continue
		}
		newEntry := v
		for _, mergeFunc := range mergeFuncs {
			newEntry = mergeFunc(newEntry, Result{})
			if newEntry.ID == "" || len(newEntry.Vulnerabilities) == 0 {
				continue nextExisting
			}
		}
		out[v.ID] = newEntry
	}
	return out
}

func (r Set) Contains(id ID) bool {
	_, ok := r[id]
	return ok
}

func (r Set) Filter(criteria ...vulnerability.Criteria) Set {
	out := Set{}
	for _, v := range r {
		vulns, err := filterVulns(v.Vulnerabilities, criteria)
		if err != nil {
			log.WithFields("vulnerability", v.ID, "error", err).Debug("failed to filter vulns")
			// if there was an error filtering vulnerabilities, keep them all
			vulns = v.Vulnerabilities
		}
		if len(vulns) == 0 {
			continue
		}
		out[v.ID] = Result{
			ID:              v.ID,
			Vulnerabilities: vulns,
			Details:         v.Details,
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
