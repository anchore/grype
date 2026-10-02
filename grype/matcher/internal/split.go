package internal

import (
	"slices"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// SplitVulnerable partitions the set into records reporting the searched version vulnerable and
// everything else. No vulnerability appears in both.
//
//   - A record's affected ranges are hydrated as separate vulnerabilities; only ranges covering the
//     version are kept.
//   - When searches disagree (e.g. a base distro's rows and a rebuild's channel a search rule selected,
//     or the channels of two rules), the highest-ranked search with a covering range decides (see
//     result.Rank).
//   - Unaffected records (NAKs) deny regardless of rank.
//
// v is the fallback for records whose details do not carry the searched version.
func SplitVulnerable(s result.Set, v *version.Version) (vulnerable, notVulnerable result.Set) {
	affected, unaffected := splitUnaffected(s)

	unaffected = filterByVersion(unaffected, v, matchesVersionConstraints)

	// a fix exactly at the installed version proves the build carries that advisory's patch
	exactlyFixed := keepByExactFixVersion(affected, v)

	candidates := filterByVersion(affected, v, matchesVersionConstraints)

	// matching one range of a vulnerability sets aside its other ranges in that namespace
	notVulnerable = affected.Filter(removeExactVulnerabilitiesByNamespace(candidates))

	if v != nil {
		notVulnerable = filterByVersion(notVulnerable, v, outsideConstraints)

		// TODO: only fixed records are kept; other not-vulnerable states (e.g. not-affected) are not kept here
		notVulnerable = notVulnerable.Filter(search.ByFixedVersion(*v))
	}

	candidates = keepMoreSpecificCandidates(candidates, notVulnerable)

	vulnerable = candidates.Remove(unaffected)

	vulnerable = removeExactlyFixed(vulnerable, exactlyFixed)

	// an unaffected record whose ranges miss this version is in neither result
	return vulnerable, removeByIDAndAlias(affected, vulnerable).Merge(unaffected).Merge(exactlyFixed)
}

func keepByExactFixVersion(affected result.Set, v *version.Version) result.Set {
	if v == nil || v.Raw == "" {
		return result.Set{}
	}
	return affected.Filter(search.ByFunc(func(vuln vulnerability.Vulnerability) (bool, string, error) {
		if slices.Contains(vuln.Fix.Versions, v.Raw) {
			return true, "", nil
		}
		return false, "does not have exact fix version", nil
	}))
}

// removeExactlyFixed drops candidates whose CVEs are all patched by an advisory fixed exactly at the
// installed version. A candidate with an additional CVE is kept (e.g. OL8 ELSA-2022-7647 shares
// CVE-2022-31813 with the exactly-fixed ELSA-2022-9682 but covers more).
func removeExactlyFixed(candidates, exactlyFixed result.Set) result.Set {
	if len(exactlyFixed) == 0 {
		return candidates
	}
	patchedCVEs := strset.New()
	for id, results := range exactlyFixed {
		patchedCVEs.Add(cveIDsOf(result.Identity(id, results)).List()...)
	}
	out := result.Set{}
	for id, results := range candidates {
		cves := cveIDsOf(result.Identity(id, results))
		// strset's receiver is the superset
		if cves.Size() > 0 && patchedCVEs.IsSubset(cves) {
			continue
		}
		out[id] = results
	}
	return out
}

// cveIDsOf drops advisory IDs (ELSA-..., RHSA-...), which label CVEs rather than being patched.
func cveIDsOf(s *strset.Set) *strset.Set {
	out := strset.New()
	s.Each(func(id string) bool {
		if strings.HasPrefix(id, "CVE-") {
			out.Add(id)
		}
		return true
	})
	return out
}

func removeExactVulnerabilitiesByNamespace(candidates result.Set) vulnerability.Criteria {
	return search.ByFunc(func(incoming vulnerability.Vulnerability) (bool, string, error) {
		vulnerable := candidates[incoming.ID]
		for _, v := range vulnerable {
			for _, v := range v.Vulnerabilities {
				// a record with several affected ranges (e.g. GHSA) is hydrated as one vulnerability per range
				if v.ID == incoming.ID && v.Namespace == incoming.Namespace {
					return false, "same vulnerability ID", nil
				}
			}
		}
		return true, "", nil
	})
}

// outsideConstraints tests that v falls outside a record's affected range; with no version nothing matches.
func outsideConstraints(v *version.Version) vulnerability.Criteria {
	if v == nil || v.Raw == "" {
		return search.ByFunc(func(vulnerability.Vulnerability) (bool, string, error) {
			return false, "", nil
		})
	}
	return search.ByFunc(func(vuln vulnerability.Vulnerability) (bool, string, error) {
		matches, err := vuln.Constraint.Satisfied(v)
		if err != nil {
			return false, err.Error(), err
		}
		return !matches, "", nil
	})
}

// removeByIDAndAlias drops from s every record whose ID is an ID or alias of a removal, and every
// record sharing an alias with a higher-ranked removal. A record sharing only an alias with an equal
// or lower-ranked removal is a separate advisory (e.g. another release line's) and is kept.
//
//nolint:gocognit
func removeByIDAndAlias(s result.Set, removals result.Set) result.Set {
	// highest removal rank by ID and alias
	removedRank := map[string]result.Rank{}
	raise := func(id string, r result.Rank) {
		if prev, ok := removedRank[id]; !ok || r.Compare(prev) > 0 {
			removedRank[id] = r
		}
	}
	for id, results := range removals {
		for _, r := range results {
			raise(id, r.Rank)
			for _, v := range r.Vulnerabilities {
				for _, alias := range v.RelatedVulnerabilities {
					raise(alias.ID, r.Rank)
				}
			}
		}
	}

	out := result.Set{}
	for id, results := range s {
		if _, ok := removedRank[id]; ok {
			continue
		}
		results = slices.DeleteFunc(slices.Clone(results), func(r result.Result) bool {
			for _, v := range r.Vulnerabilities {
				for _, alias := range v.RelatedVulnerabilities {
					if removed, ok := removedRank[alias.ID]; ok && r.Rank.Compare(removed) < 0 {
						return true
					}
				}
			}
			return false
		})
		if len(results) == 0 {
			continue
		}
		out[id] = results
	}
	return out
}

// keepMoreSpecificCandidates drops candidates outranked by a not-vulnerable record for the same ID or
// by another candidate, moving their details onto the survivors.
func keepMoreSpecificCandidates(candidates, notVulnerable result.Set) result.Set {
	out := result.Set{}
	for id, results := range candidates {
		var maxRank result.Rank
		for i, candidate := range results {
			if i == 0 || candidate.Rank.Compare(maxRank) > 0 {
				maxRank = candidate.Rank
			}
		}
		var droppedDetails match.Details
		results = slices.DeleteFunc(results, func(candidate result.Result) bool {
			for _, fixed := range notVulnerable[id] {
				if candidate.Rank.Compare(fixed.Rank) < 0 {
					droppedDetails = append(droppedDetails, candidate.Details...)
					vulnerability.LogDropped(id, "SplitVulnerable", "the most specific stream describing this package reports the version fixed", nil)
					return true
				}
			}

			return false
		})

		// TODO: keep every vulnerability found as evidence for a match; the data model does not support this today
		results = slices.DeleteFunc(results, func(candidate result.Result) bool {
			if candidate.Rank.Compare(maxRank) < 0 {
				droppedDetails = append(droppedDetails, candidate.Details...)
				return true
			}
			return false
		})

		if len(results) == 0 {
			log.WithFields("vulnerability", id).Trace("dropping vulnerability due to less specific vulnerable record")
			continue
		}

		// clone: Details is shared with the source set
		if len(droppedDetails) > 0 {
			for i := range results {
				results[i].Details = append(slices.Clone(results[i].Details), droppedDetails...)
			}
		}
		out[id] = results
	}
	return out
}

func splitUnaffected(s result.Set) (affected, unaffected result.Set) {
	affected, unaffected = result.Set{}, result.Set{}
	for id, results := range s {
		for _, r := range results {
			a, u := splitVulns(r.Vulnerabilities)
			if len(a) > 0 {
				affected[id] = append(affected[id], withVulns(r, a))
			}
			if len(u) > 0 {
				unaffected[id] = append(unaffected[id], withVulns(r, u))
			}
		}
	}
	return affected, unaffected
}

func splitVulns(vulns []vulnerability.Vulnerability) (affected, unaffected []vulnerability.Vulnerability) {
	for _, v := range vulns {
		if v.Unaffected {
			unaffected = append(unaffected, v)
		} else {
			affected = append(affected, v)
		}
	}
	return affected, unaffected
}

func withVulns(r result.Result, vulns []vulnerability.Vulnerability) result.Result {
	out := r
	out.Vulnerabilities = vulns
	return out
}

// filterByVersion tests each result against the version its own search used, falling back to v.
func filterByVersion(s result.Set, v *version.Version, criteria func(*version.Version) vulnerability.Criteria) result.Set {
	out := result.Set{}
	for id, results := range s {
		var row []result.Result
		for _, r := range results {
			row = append(row, filterOne(id, r, criteria(searchedVersion(r, v)))...)
		}
		if len(row) > 0 {
			out[id] = row
		}
	}
	return out
}

// searchedVersion returns the version of the package r's search was for, falling back to v. This lets
// one split span a package and its upstreams, whose versions differ (e.g. rpm source packages have no
// epoch, a subpackage or binNMU is versioned apart from its source). The version keeps v's format and
// comparison config.
func searchedVersion(r result.Result, v *version.Version) *version.Version {
	if r.Package == nil || r.Package.Version == "" {
		return v
	}
	raw := r.Package.Version

	switch {
	case v != nil && raw == v.Raw:
		return v
	case v != nil:
		return version.NewWithConfig(raw, v.Format, v.Config)
	}
	return version.New(raw, pkg.VersionFormat(*r.Package))
}

func filterOne(id string, r result.Result, criteria vulnerability.Criteria) []result.Result {
	return result.Set{id: {r}}.Filter(criteria)[id]
}
