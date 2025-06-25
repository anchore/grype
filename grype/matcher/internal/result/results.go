package result

import (
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

type Result struct {
	ID              ResultID
	Vulnerabilities []vulnerability.Vulnerability
	Details         match.Details
}

type ResultID string

type ResultSet map[ResultID]Result

func (r ResultSet) ToMatches(p pkg.Package) []match.Match {
	var out []match.Match
	for _, v := range r {
		if len(v.Vulnerabilities) == 0 {
			continue
		}
		out = append(out, match.Match{
			Vulnerability: v.Vulnerabilities[0], // TODO merge function?
			Package:       p,
			Details:       v.Details,
		})
	}
	// sort.Sort(match.ByElements(out))
	return out
}

func (r ResultSet) Remove(incoming ResultSet) ResultSet {
	out := ResultSet{}
	for id, v := range r {
		if incoming.Contains(id) {
			continue
		}
		out[id] = v
	}
	return out
}

func (r ResultSet) Merge(incoming ResultSet, mergeFuncs ...func(existing, incoming Result) Result) ResultSet {
	out := ResultSet{}
	if len(mergeFuncs) == 0 {
		// with no other merge functions specified, append all vulnerability results and details
		mergeFuncs = []func(existing, incoming Result) Result{
			func(existing, incoming Result) Result {
				id := existing.ID
				if id == "" {
					id = incoming.ID
				}
				return Result{
					ID:              id,
					Vulnerabilities: append(existing.Vulnerabilities, incoming.Vulnerabilities...),
					Details:         append(existing.Details, incoming.Details...),
				}
			},
		}
	}
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

func (r ResultSet) Contains(id ResultID) bool {
	_, ok := r[id]
	return ok
}

func (r ResultSet) Filter(criteria ...vulnerability.Criteria) ResultSet {
	out := ResultSet{}
	for _, v := range r {
		vulns, err := filterVulns(v.Vulnerabilities, criteria)
		if err != nil {
			log.WithFields(logger.Fields{
				"vulnerability": v.ID,
				"error":         err,
			}).Debug("failed to filter vulns")
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

func MergeDisclosuresForFixVersions(v *version.Version) func(disclosures, advisoryOverlay Result) Result {
	return func(disclosures, advisoryOverlay Result) Result {
		out := Result{ID: disclosures.ID}

		// keep only the disclosures that Result the criteria of the resolution
	disclosureLoop:
		for _, disclosure := range disclosures.Vulnerabilities {
			fixVersions := strset.New()
			var state vulnerability.FixState
			for _, advisory := range advisoryOverlay.Vulnerabilities {
				switch advisory.Fix.State {
				case vulnerability.FixStateWontFix, vulnerability.FixStateUnknown:
					// these do not negate disclosures, so we will skip them
					continue
				}
				isVulnerable, err := advisory.Constraint.Satisfied(v)
				if err != nil {
					log.WithFields(logger.Fields{
						"vulnerability": advisory.ID,
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

				fixVersions.Add(advisory.Fix.Versions...)
				if state != vulnerability.FixStateFixed {
					state = advisory.Fix.State
				}
			}

			if state != vulnerability.FixStateFixed {
				// TODO: this needs to get rethought as we come up with more reasons here (e.g. not applicable, not vulnerable, etc.)
				continue
			}

			patchedRecord := disclosure

			fixVersions.Remove("")
			fixVersionList := fixVersions.List()
			sort.Strings(fixVersionList) // TODO: use version sort, not lexically... or does this matter... when converting to a model for presentation this will be handled.

			patchedRecord.Fix.State = state
			patchedRecord.Fix.Versions = fixVersionList

			// this disclosure does not have a resolution that satisfies it, so we will keep it... patching on any fixes that we are aware of
			out.Vulnerabilities = append(out.Vulnerabilities, patchedRecord)
			out.Details = append(out.Details, advisoryOverlay.Details...)
		}

		return out
	}
}
