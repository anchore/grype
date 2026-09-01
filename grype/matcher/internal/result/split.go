package result

import (
	"sort"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// SplitVulnerable partitions the set into the records that say the searched version is vulnerable
// and everything else.
//
// The partition is made per affected version window, per release stream, and against the provider's
// unaffected records:
//
//   - One provider record can describe several affected version windows at once -- one build per
//     release line it patched -- each hydrated into its own vulnerability.Vulnerability with its own
//     constraint and fix. Only the windows this version falls inside are kept, so the fix a match
//     reports is the fix of the window it matched.
//
//   - A package can be described by more than one release stream at once (a base distro's rows and a
//     rebuild's channel), and the streams can disagree. The question is asked of one stream at a
//     time, most specific first, and the first stream with an answer gives it; a stream whose ranges
//     do not cover this version has no answer and the question falls through to the next one down.
//     How confidently a stream speaks for the package is read off the detail the search that
//     produced its records recorded it on (see confidenceOf).
//
//   - The set holds the provider's unaffected records (NAKs) alongside its affected ones. Those can
//     only deny, and are not ranked against the streams -- see the denials below.
//
// The second return is everything not reported, not merely what is fixed: it also holds records
// whose ranges do not cover this version at all, with no fix recorded. Callers use it to build the
// ignores applied to packages this one owns files for. A vulnerability reported in the first return
// never appears in the second.
//
// v is the version to test against for records that do not name their own; see searchedVersion for
// the ones that do.
func (s Set) SplitVulnerable(v *version.Version) (vulnerable, notVulnerable Set) {
	affected, unaffected := s.partitionUnaffected()

	// the records the provider calls unaffected can only deny, never report: each is the vendor
	// stating a vulnerability does not apply. They are not ranked against the streams either --
	// "not affected" is not a claim about one release line, so the most specific stream does not
	// overrule it. One whose ranges do not cover this version denies nothing (e.g. the apk "< 0"
	// NAK, satisfied by no version at all) and reaches callers through the not-vulnerable leg
	denials := unaffected.atVersion(v, vulnerableAtVersion)

	candidates := Set{}
	for id, results := range affected {
		if kept := mostSpecificVulnerable(id, results, v); len(kept) > 0 {
			candidates[id] = kept
		}
	}

	// denial is by vulnerability identity rather than by entry: a provider that keys its naks by its
	// own IDs (rootio) carries the CVE as an alias, so the nak and the disclosure it answers arrive
	// under different entries and only identity connects them
	vulnerable = candidates.Remove(denials)
	for id := range candidates {
		if _, kept := vulnerable[id]; !kept {
			vulnerability.LogDropped(id, "SplitVulnerable", "the provider reports this package unaffected at this version", nil)
		}
	}

	// An unaffected record whose ranges do not cover this version is left out of both legs: it is a
	// statement about other builds, and callers reconcile other sources against the not-vulnerable
	// leg, so letting it through would suppress a finding the provider never answered.
	return vulnerable, affected.Remove(vulnerable).Merge(denials)
}

// vulnerableAtVersion is the criteria testing a record's affected range against the searched
// version. A search made without a version cannot rule anything out, so every record stays a
// candidate.
func vulnerableAtVersion(v *version.Version) vulnerability.Criteria {
	if v == nil || v.Raw == "" {
		return search.ByFunc(func(vulnerability.Vulnerability) (bool, string, error) {
			return true, "", nil
		})
	}
	return search.ByVersion(*v)
}

// fixedAtVersion is the criteria testing a record's fix against the searched version. A search made
// without a version cannot find anything fixed at it, so no record matches.
func fixedAtVersion(v *version.Version) vulnerability.Criteria {
	if v == nil || v.Raw == "" {
		return search.ByFunc(func(vulnerability.Vulnerability) (bool, string, error) {
			return false, "no version to compare a fix against", nil
		})
	}
	return search.ByFixedVersion(*v)
}

// mostSpecificVulnerable returns the vulnerable records of the most specific stream that has an
// answer for this version, or nothing when that answer is that the version is not vulnerable. It is
// given only the provider's affected records; the unaffected ones are handled by denials.
func mostSpecificVulnerable(id string, results []Result, v *version.Version) []Result {
	for _, tier := range tiers(results) {
		vulnerable := atVersion(id, tier.results, v, vulnerableAtVersion)
		if len(vulnerable) > 0 {
			return vulnerable
		}
		if len(atVersion(id, tier.results, v, fixedAtVersion)) > 0 {
			// this stream has an answer and it is that the version is past its fix; less specific
			// streams describe builds this package is not, so they do not get to override it
			vulnerability.LogDropped(id, "SplitVulnerable", "the most specific stream describing this package reports the version fixed", nil)
			return nil
		}
		// this stream's ranges do not cover this version -- it is describing some other release
		// line and has nothing to say here, so ask the next one down
	}
	return nil
}

// partitionUnaffected splits the set into the provider's affected records and its unaffected ones.
// A single Result can hold both, since one search returns whatever the stores hold for the
// vulnerability, so the split is over the vulnerabilities rather than over the results.
func (s Set) partitionUnaffected() (affected, unaffected Set) {
	affected, unaffected = Set{}, Set{}
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

// atVersion keeps the entries whose records match a version-dependent criteria.
func (s Set) atVersion(v *version.Version, criteria func(*version.Version) vulnerability.Criteria) Set {
	out := Set{}
	for id, results := range s {
		if kept := atVersion(id, results, v, criteria); len(kept) > 0 {
			out[id] = kept
		}
	}
	return out
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

// withVulns returns a copy of r carrying only the given vulnerabilities, keeping the details it was
// found by: the details describe the search, and the search is what turned up every one of them.
func withVulns(r Result, vulns []vulnerability.Vulnerability) Result {
	out := r
	out.Vulnerabilities = vulns
	return out
}

// tier is one stream's records for a single vulnerability.
type tier struct {
	confidence float64
	results    []Result
}

// tiers groups the records by the confidence of the search that found them, most confident first.
// Ties keep their first-seen order, so the returned matches and their details are stable across
// runs.
func tiers(results []Result) []tier {
	var out []tier
	index := make(map[float64]int)

	for _, r := range results {
		c := confidenceOf(r)
		i, ok := index[c]
		if !ok {
			index[c] = len(out)
			out = append(out, tier{confidence: c})
			i = len(out) - 1
		}
		out[i].results = append(out[i].results, r)
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].confidence > out[j].confidence })
	return out
}

// confidenceOf is how strongly a record's own search speaks for this package, read back off the
// detail the search recorded it on (see match.Details.SearchConfidence) -- the same way
// searchedVersion reads the searched version off the details.
//
// It is deliberately not read from the confidences of the details that describe the search: those
// state how certain a match of that shape is (a CPE match is less certain than a distro match) and
// say nothing about which of several searches for one package found this record.
//
// A record whose details record no confidence ranks at zero, so a set where nothing was ranked is
// one uniform tier -- the same answer the split gives when nothing distinguishes its records.
func confidenceOf(r Result) float64 {
	c, _ := r.Details.SearchConfidence()
	return c
}

// atVersion keeps the records matching a version-dependent criteria, testing each against the
// version its own search was made with (see searchedVersion) and falling back to v for the records
// that name none. Results are filtered one at a time because those versions can differ within a
// single tier -- an rpm's source-package records are only commensurate with the epoch-less version
// they were searched at.
func atVersion(id string, results []Result, v *version.Version, criteria func(*version.Version) vulnerability.Criteria) []Result {
	var out []Result
	for _, r := range results {
		out = append(out, filterOne(id, r, criteria(searchedVersion(r, v)))...)
	}
	return out
}

// searchedVersion returns the version a record's own search was made with, falling back to v.
//
// It is read back off the match details, which already describe that search: a caller passes
// search.WithVersion to convey the version without constraining results, and the provider records
// it on the details it builds (see extractSearchParameters). Nothing else has to carry it, and a
// record cannot end up tested against a version no detail of it admits to.
//
// This lets one call to SplitVulnerable span a package and its upstreams: an rpm's source-package
// search drops the epoch, since sourceRPMs omit epochs even where the binary has one (see
// rpm.matchUpstreamPackages), so records found under the source name are only commensurate with
// that version and not with the binary's.
//
// Which details record it, and which record the cataloged version instead, is spelled out on
// match.Details.SearchedPackageVersion.
func searchedVersion(r Result, v *version.Version) *version.Version {
	raw, ok := r.Details.SearchedPackageVersion()
	if !ok || (v != nil && raw == v.Raw) {
		return v
	}

	// the comparison terms come from the split's own version, which is the same package in the same
	// ecosystem searched under a different name; only the raw version differs
	switch {
	case v != nil:
		return version.NewWithConfig(raw, v.Format, v.Config)
	case r.Package != nil:
		return version.New(raw, pkg.VersionFormat(*r.Package))
	}
	return nil
}

// filterOne keeps the record if it matches the criteria, preserving the detail-patching Filter
// performs so the searched-by version still lands on the match details.
func filterOne(id string, r Result, criteria vulnerability.Criteria) []Result {
	return Set{id: {r}}.Filter(criteria)[id]
}
