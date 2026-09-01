package result

import (
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
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
	Details match.Details

	// Package is the package that was used to search for vulnerabilities.
	Package *pkg.Package
}

type Set map[string][]Result

// ToMatches converts the set into matches, one per finding.
//
// Each record contributes a match carrying only the details that describe *that* record. Records
// that turn out to be the same finding -- same vulnerability, same source, same package -- are then
// folded together by match.Matches, which unions their fixed-in versions and details. Attaching the
// whole set's details to every match instead would make each duplicate claim the others' evidence.
func (s Set) ToMatches() []match.Match {
	out := match.NewMatches()

	for _, results := range s {
		for _, r := range results {
			if r.Package == nil {
				continue // skip results without a package
			}
			for _, v := range r.Vulnerabilities {
				out.Add(match.Match{
					Vulnerability: v,
					Package:       *r.Package,
					// how confidently the search that found this record speaks for the package is
					// what ranked it during the split; it describes no search of its own, so it is
					// not evidence to report
					Details: r.Details.WithoutSearchConfidence(),
				})
			}
		}
	}

	// deterministic output order (map iteration above is not ordered)
	return out.Sorted()
}

// Vulnerabilities returns a flattened slice of all vulnerabilities in the set
func (s Set) Vulnerabilities() []vulnerability.Vulnerability {
	var out []vulnerability.Vulnerability
	for _, results := range s {
		for _, r := range results {
			out = append(out, r.Vulnerabilities...)
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
	// collect all incoming identifiers into one unified set
	incomingIdentifiers := strset.New()
	for id, results := range incoming {
		incomingIdentifiers.Add(getIdentity(id, results).List()...)
	}

	// keep only entries whose identities don't overlap with incoming
	out := Set{}
	for id, results := range s {
		identity := getIdentity(id, results)
		if strset.Intersection(identity, incomingIdentifiers).IsEmpty() {
			out[id] = results
		}
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

// getIdentity returns all identifiers (ID + aliases) for a vulnerability entry
func getIdentity(id string, results []Result) *strset.Set {
	identity := strset.New()
	identity.Add(id)
	identity.Add(extractAliases(results).List()...)
	return identity
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

// ContainsByIdentity checks if the set contains an entry with overlapping identity (ID or aliases)
func (s Set) ContainsByIdentity(searchID string, searchResults []Result) bool {
	searchIdentity := getIdentity(searchID, searchResults)

	for id, results := range s {
		identity := getIdentity(id, results)
		if !strset.Intersection(identity, searchIdentity).IsEmpty() {
			return true
		}
	}
	return false
}

// Intersection returns entries that exist in both sets (by identity overlap)
func (s Set) Intersection(other Set) Set {
	otherIdentifiers := strset.New()
	for id, results := range other {
		otherIdentifiers.Add(getIdentity(id, results).List()...)
	}

	out := Set{}
	for id, results := range s {
		identity := getIdentity(id, results)
		if !strset.Intersection(identity, otherIdentifiers).IsEmpty() {
			out[id] = results
		}
	}
	return out
}

// IdentitiesOverlap returns true if two results share any common identifiers, where identity
// includes both the primary ID and any aliases (from RelatedVulnerabilities). This can be used
// as a shouldUpdate predicate for Update when matching results by ID or alias relationships.
func IdentitiesOverlap(existing Result, incoming Result) bool {
	existingIdentity := getIdentity(existing.ID, []Result{existing})
	incomingIdentity := getIdentity(incoming.ID, []Result{incoming})
	return !strset.Intersection(existingIdentity, incomingIdentity).IsEmpty()
}

// Update applies an update function to each result in the set where shouldUpdate returns true
// for the existing-incoming result pair. The updateFunc can modify fields of the existing result
// in-place while preserving other fields. Returns a new Set with updated results.
//
// Example with identity-based matching:
//
//	updated := base.Update(incoming, IdentitiesOverlap, func(existing *Result, incoming Result) {
//	    existing.Vulnerabilities[0].Fix = incoming.Vulnerabilities[0].Fix
//	})
func (s Set) Update(incoming Set, shouldUpdate func(existing Result, incoming Result) bool, updateFunc func(existing *Result, incoming Result)) Set {
	out := make(Set)

	// Copy everything from base set
	for id, results := range s {
		out[id] = append([]Result(nil), results...)
	}

	// For each entry in base, check all incoming entries with shouldUpdate
	for id, existingResults := range out {
		for i := range existingResults {
			for _, incomingResults := range incoming {
				for _, incomingResult := range incomingResults {
					if shouldUpdate(existingResults[i], incomingResult) {
						updateFunc(&existingResults[i], incomingResult)
					}
				}
			}
		}
		out[id] = existingResults
	}

	return out
}

// Map returns a new Set with fn applied to a copy of every result. Because the copy is shallow, fn
// must not mutate the elements of a slice field (e.g. Vulnerabilities, Details) in place — replace the
// whole slice instead — otherwise it will corrupt the source set's shared backing arrays.
func (s Set) Map(fn func(r *Result)) Set {
	out := make(Set, len(s))
	for id, results := range s {
		updated := make([]Result, len(results))
		for i, r := range results {
			fn(&r)
			updated[i] = r
		}
		out[id] = updated
	}
	return out
}

// MarkIndirect marks every record's evidence as an indirect match.
//
// The match type is otherwise derived by comparing the name a record was searched by against the
// cataloged package's, which cannot tell the two apart when a package is its own upstream -- so the
// upstream pass says so explicitly rather than relying on the names differing.
func (s Set) MarkIndirect() Set {
	return s.Map(func(r *Result) {
		// replace the slice rather than writing through it: Map's copy is shallow, so mutating in
		// place would corrupt the source set's backing array
		details := make([]match.Detail, len(r.Details))
		for i, d := range r.Details {
			d.Type = match.ExactIndirectMatch
			details[i] = d
		}
		r.Details = details
	})
}

// Filter keeps the records matching every criteria.
//
// A version criteria here answers "does any window of this record cover me", which cannot tell a
// record already fixed at this version from one describing a release line the package is not on,
// and drops the records that carry that distinction. SplitVulnerable asks the question per window
// and keeps both legs.
func (s Set) Filter(criteria ...vulnerability.Criteria) Set {
	out := Set{}
	for id, results := range s {
		var filteredResults []Result

		for _, result := range results {
			vulns, details, err := filterVulns(result.Vulnerabilities, result.Details, criteria)
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
				Details:         details,
				Package:         result.Package,
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

func filterVulns(vulnerabilities []vulnerability.Vulnerability, details match.Details, criteria []vulnerability.Criteria) ([]vulnerability.Vulnerability, match.Details, error) {
	var out []vulnerability.Vulnerability
nextVulnerability:
	for _, v := range vulnerabilities {
		for _, c := range criteria {
			matches, dropReason, err := c.MatchesVulnerability(v)
			if err != nil {
				return nil, details, err
			}
			if !matches {
				vulnerability.LogDropped(v.ID, "filterVulns", dropReason, c)
				continue nextVulnerability
			}

			if versionCriteria, ok := c.(*search.VersionCriteria); ok {
				// version info needs to be captured when applicable, until there is a better audit mechanism
				details = patchDetailVersion(details, versionCriteria.Version.Raw)
			}
		}
		out = append(out, v)
	}
	return out, details, nil
}

// patchDetailVersion fills in the searched-by package version on match details that are missing it.
func patchDetailVersion(details match.Details, version string) match.Details {
	for i := range details {
		d := &details[i]
		switch sb := d.SearchedBy.(type) {
		case match.DistroParameters:
			if sb.Package.Version == "" {
				sb.Package.Version = version
				d.SearchedBy = sb
			}
		case match.EcosystemParameters:
			if sb.Package.Version == "" {
				sb.Package.Version = version
				d.SearchedBy = sb
			}
		case match.CPEParameters:
			if sb.Package.Version == "" {
				sb.Package.Version = version
				d.SearchedBy = sb
			}
		}
	}
	return details
}
